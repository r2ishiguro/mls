// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package protocol

import (
	"io"
	"errors"
	"log"

	"github.com/r2ishiguro/mls"
	"github.com/r2ishiguro/mls/ds"
	"github.com/r2ishiguro/mls/crypto"
	"github.com/r2ishiguro/mls/auth"
	"github.com/r2ishiguro/mls/packet"
)

var (
	ErrKeyNotFound = errors.New("key not found")
	ErrUserNotFound = errors.New("user not found")
	ErrGroupNotFound = errors.New("group not found")
	ErrAuthFailure = errors.New("authentication failed")
	ErrMerkleProofVerificationFailure = errors.New("Merkle proof verification failed")
	ErrInconsistentPath = errors.New("inconsistent path")
	ErrUnknownHandshakeProtocol = errors.New("unknown protocol")
	ErrEpochOutOfSync = errors.New("epoch out of sync")
)

type Protocol struct {
	self string
	channels map[string]*GroupChannel
	uik *mls.UserInitKey		// cache of directory[self]
	privKeyMap map[string]map[mls.CipherSuite][]byte	// keep private keys corresponding to all UIKs generated during the protocol
	ds *ds.DeliveryService
	directory *ds.DirectoryService
	sig *mls.Signature
	auth auth.AuthenticationService
	aead crypto.DataEncryption
}

var (
	defaultCiphers = []mls.CipherSuite{	// it's not guaranteed to generate keys for all ciphers
		mls.CipherX25519WithSHA256,
		mls.CipherP256R1WithSHA256,
	}
)

func New(self string, dir *ds.DirectoryService, sig *mls.Signature, auth auth.AuthenticationService, aead crypto.DataEncryption) *Protocol {
	return &Protocol{
		self: self,
		channels: make(map[string]*GroupChannel),
		uik: nil,
		privKeyMap: make(map[string]map[mls.CipherSuite][]byte),
		directory: dir,
		sig: sig,
		auth: auth,
		aead: aead,
	}
}

func (p *Protocol) Connect(dsAddr string) error {
	// generate a new UserInitKey and register it
	if _, err := p.generateUIK(); err != nil {
		return err
	}
	p.ds = ds.NewClient(dsAddr)
	return nil
}

func (p *Protocol) Run() error {
	return p.ds.Run(p)
}

// create a new GroupChannel and initialize it with the self key
func (p *Protocol) CreateGroupChannel(gid string, cipher mls.CipherSuite) (*GroupChannel, error) {
	channel, err := NewGroupChannel(p, gid, cipher)
	if err != nil {
		return nil, err
	}
	if p.uik == nil {
		return nil, ErrKeyNotFound	// not finished Connect()??
	}
	privKey := p.getPrivateKey(p.uik, cipher)
	if privKey == nil {
		return nil, ErrKeyNotFound
	}
	if err := channel.Initialize(privKey, p.uik.IdentityKey); err != nil {	// this uik must be the one on the directory
		return nil, err
	}

	// register the GIK as we just created a new group
	if err := channel.RegisterGIK(); err != nil {
		return nil, err
	}

	p.channels[gid] = channel
	return channel, nil
}

// create a new GroupChannel with a given GIK
func (p *Protocol) CreateGroupChannelWithGIK(gik *mls.GroupInitKey, uik *mls.UserInitKey) (*GroupChannel, error) {
	channel, err := NewGroupChannelWithGIK(p, gik)
	if err != nil {
		return nil, err
	}
	privKey := p.getPrivateKey(uik, gik.Cipher)
	if privKey == nil {
		return nil, ErrKeyNotFound
	}
	if err := channel.Initialize(privKey, uik.IdentityKey); err != nil {
		return nil, err
	}

	p.channels[gik.GroupId] = channel
	return channel, nil
}

// join an existing group (UserAdd)
func (p *Protocol) Join(gid string) (*GroupChannel, error) {
	// lookup the group
	gik, err := p.directory.LookupGroup(gid)
	if err != nil {
		return nil, err
	}
	if gik == nil {
		return nil, ErrGroupNotFound
	}

	// we should renew the UIK and register it to the directory service
	uik, err := p.generateUIK()
	if err != nil {
		return nil, err
	}
	channel, err := p.CreateGroupChannelWithGIK(gik, uik)
	if err != nil {
		return nil, err
	}

	if err := channel.Join(); err != nil {
		return nil, err
	}
	return channel, nil
}

func (p *Protocol) UId() string {
	return p.self
}

func (p *Protocol) Close() {
	for _, c := range p.channels {
		c.Close()
	}
	if p.uik != nil {
		// self user ID / UIK should've been registered
		p.directory.DeleteUser(p.self)
	}
}

func (p *Protocol) verifyUIK(uik *mls.UserInitKey) (string, error) {
	uid, err := p.auth.Lookup(uik.IdentityKey)
	if err != nil {
		return "", err
	}
	tbs, err := packet.UserInitKeyTBS(uik)
	if err != nil {
		return "", err
	}
	sig, err := mls.NewSignature(uik.SignatureAlgorithm)
	if err != nil {
		return "", err
	}
	sig.Initialize(uik.IdentityKey, nil)
	return uid, sig.Verify(tbs, uik.Signature)
}

func (p *Protocol) generateUIK() (*mls.UserInitKey, error) {
	uik, privKeys, err := GenerateUserInitKey(defaultCiphers, p.sig)
	if err != nil {
		return nil, err
	}
	if err := p.directory.RegisterUIK(p.self, uik); err != nil {
		return nil, err
	}
	p.uik = uik	// keep the UIK that has been registered
	p.privKeyMap[string(uik.InitKeys[uik.Ciphers[0]])] = privKeys
	return uik, nil
}

func (p *Protocol) getPrivateKey(uik *mls.UserInitKey, cipher mls.CipherSuite) []byte {
	ks, ok := p.privKeyMap[string(uik.InitKeys[uik.Ciphers[0]])]
	if !ok {
		return nil
	}
	key, ok := ks[cipher]
	if !ok {
		return nil
	}
	return key
}

func (p *Protocol) marshal(g *GroupState, data interface{}) ([]byte, error) {
	var msg packet.HandshakeMessage
	
	switch data.(type) {
	case *packet.GroupAdd:
		msg.Type = packet.HandshakeGroupAdd
	case *packet.UserAdd:
		msg.Type = packet.HandshakeUserAdd
	case *packet.Update:
		msg.Type = packet.HandshakeUpdate
	case *packet.Delete:
		msg.Type = packet.HandshakeDelete
	case *packet.None:
		msg.Type = packet.HandshakeNone
	default:
		return nil, packet.ErrUnknownMessageType
	}
	msg.Data = data
	msg.PriorEpoch = g.Epoch()

	gik, err := g.ConstructGroupInitKey()
	if err != nil {
		return nil, err
	}
	msg.GIK = gik

	idx, proof, err := g.Proof()
	if err != nil {
		return nil, err
	}
	msg.SignerIndex = uint32(idx)
	msg.MerkleProof = proof
	msg.IdentityKey = p.sig.PublicKey()
	msg.SignatureAlgorithm = p.sig.Algorithm()

	return packet.MarshalHandshake(&msg, p.sig)
}

// the callback from the DS
func (p *Protocol) Handler(r io.Reader) error {
	for {
		msg, pkt, err := packet.UnmarshalHandshake(r)
		if err != nil {
			return err
		}
		channel, ok := p.channels[msg.GIK.GroupId]	// we need to identify the group before verifying the message
		if !ok {
			channel = nil
		}
		if err := GroupChannelHandler(p, channel, msg, pkt); err != nil {
			if err == io.EOF {
				delete(p.channels, msg.GIK.GroupId)
			} else {
				log.Printf("handshake: [%s] handler error, msg = %d: %s", p.self, msg.Type, err)
				// continue...
			}
		}
	}
	return nil
}
