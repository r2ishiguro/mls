// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package protocol

import (
	"io"
	"bytes"
	"errors"
	"log"
	"fmt"

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
	ds *ds.DeliveryService
	directory *ds.DirectoryService
	sig *mls.Signature
	auth auth.AuthenticationService
	aead crypto.DataEncryption
	channels map[string]*GroupChannel
	privKeyMap map[string]map[mls.CipherSuite][]byte
	uik *mls.UserInitKey		// cache of directory[self]
	self string
}

type GroupChannel struct {
	gid string
	state *GroupState
	dh crypto.GroupOperation	// corresponding to the cipher suite
	peers map[string]int		// map of UID to the leaf index
	message *Message
	protocol *Protocol
	epoch int
	cipher mls.CipherSuite
}

const (
	defaultPort = 9898
)

var (
	defaultCiphers = []mls.CipherSuite{	// it's not guaranteed to generate keys for all ciphers
		mls.CipherX25519WithSHA256,
		mls.CipherP256R1WithSHA256,
	}
)

func New(self string, dir *ds.DirectoryService, sig *mls.Signature, auth auth.AuthenticationService, aead crypto.DataEncryption) *Protocol {
	return &Protocol{
		self: self,
		directory: dir,
		sig: sig,
		auth: auth,
		aead: aead,
		channels: make(map[string]*GroupChannel),
		privKeyMap: make(map[string]map[mls.CipherSuite][]byte),
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
func (p *Protocol) NewGroupChannelWithGID(gid string, cipher mls.CipherSuite) (*GroupChannel, error) {
	channel := p.newGroupChannel(gid, cipher)
	g, err := NewGroupState(gid, cipher, p.sig)
	if err != nil {
		return nil, err
	}
	channel.state = g

	if p.uik == nil {
		return nil, ErrKeyNotFound	// not finished Connect()??
	}
	if err := channel.initializeWithUIK(p.uik); err != nil {	// this uik must be the one on the directory
		return nil, err
	}

	// register the GIK as we just created a new group
	gik, err := channel.state.ConstructGroupInitKey()
	if err != nil {
		return nil, err
	}
	p.directory.RegisterGIK(gik.GroupId, gik)
	return channel, nil
}

func (p *Protocol) newGroupChannel(gid string, cipher mls.CipherSuite) *GroupChannel {
	channel := &GroupChannel{
		gid: gid,
		protocol: p,
		cipher: cipher,
		peers: make(map[string]int),
	}
	p.channels[gid] = channel
	return channel
}

// create a new GroupChannel with a given GroupInitKey
func (p *Protocol) newGroupChannelWithGIK(gik *mls.GroupInitKey) (*GroupChannel, error) {
	channel := p.newGroupChannel(gik.GroupId, gik.Cipher)
	g, err := NewGroupStateWithGIK(gik, p.sig)
	if err != nil {
		return nil, err
	}
	channel.state = g
	return channel, nil
}

func (c *GroupChannel) initializeWithUIK(uik *mls.UserInitKey) error {
	p := c.protocol
	privKey := p.getPrivateKey(uik, c.cipher)
	if privKey == nil {
		return ErrKeyNotFound
	}
	idx, err := c.state.AddSelf(privKey, uik.IdentityKey)
	if err != nil {
		return err
	}
	c.peers[p.self] = idx
	return nil
}

// add members (GroupAdd)
func (c *GroupChannel) AddMembers(members []string) error {
	p := c.protocol
	// UIKs will be renewed during the protocol, therefore keep them before the protocol starts
	var uiks []*mls.UserInitKey
	for _, member := range members {
		uik, err := p.directory.LookupUser(member)
		if err != nil {
			return err
		}
		if uik == nil {
			continue
		}
		uid, err := p.verifyUIK(uik)
		if err != nil {
			return err
		}
		if uid != member {
			return ErrAuthFailure
		}
		uiks = append(uiks, uik)
	}
	g := c.state
	for _, uik := range uiks {
		ng, err := g.Copy()
		if err != nil {
			return err
		}
		if _, err := ng.AddUser(uik); err != nil {
			return err
		}
		pkt, err := c.marshal(g, &packet.GroupAdd{uik})
		if err != nil {
			return err
		}
		// immitate that each client receives the packet
		if err := ng.KeyScheduling(true, pkt); err != nil {
			return err
		}
		if err := p.ds.Send(pkt); err != nil {
			return err
		}
		g = ng
	}
	return nil
}

// update the key pair of self
func (c *GroupChannel) Update(privKeys [][]byte) error {
	ng, err := c.state.Copy()
	if err != nil {
		return err
	}
	if err := ng.UpdateSelf(privKeys); err != nil {
		return err
	}
	path := ng.GetSelfPath()
	pkt, err := c.marshal(c.state, &packet.Update{path})
	if err != nil {
		return err
	}
	if err := c.protocol.ds.Send(pkt); err != nil {
		return err
	}
	return nil
}

func (c *GroupChannel) Delete(member string) error {
	// lookup the leaf index from the UID
	idx, ok := c.peers[member]
	if !ok {
		return ErrUserNotFound
	}
	ng, err := c.state.Copy()
	if err != nil {
		return err
	}
	if err := ng.DeleteUser(idx); err != nil {
		return err
	}
	path := ng.GetPath(idx)
	pkt, err := c.marshal(c.state, &packet.Delete{uint32(idx), path})
	if err != nil {
		return err
	}
	if err := c.protocol.ds.Send(pkt); err != nil {
		return err
	}
	return nil
}

func (c *GroupChannel) List() []string {
	var res []string
	for uid, _ := range c.peers {
		res = append(res, uid)
	}
	return res
}

func (c *GroupChannel) Close() {
	if c.message != nil {
		c.message.Close()
	}
	delete(c.protocol.channels, c.gid)	// remove from the channels to prevent double Close
	c.Delete(c.protocol.self)		// then broadcast the Delete message too all but self
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

	channel, err := p.newGroupChannelWithGIK(gik)
	if err != nil {
		return nil, err
	}

	// should renew the UIK and register it to the directory service
	uik, err := p.generateUIK()
	if err != nil {
		return nil, err
	}
	if err := channel.initializeWithUIK(uik); err != nil {
		return nil, err
	}

	path := channel.state.GetSelfPath()
	pkt, err := channel.marshal(channel.state, &packet.UserAdd{path})	// use the updated GIK
	if err != nil {
		return nil, err
	}
	if err := p.ds.Send(pkt); err != nil {
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

// the callback from the DS
func (p *Protocol) Handler(r io.Reader) error {
	for {
		msg, pkt, err := packet.UnmarshalHandshake(r)
		if err != nil {
			return err
		}
		if err := p.handler(msg, pkt); err != nil {
			log.Printf("handshake: [%s] handler error: %s", p.self, err)
			// continue...
		}
	}
}

func (p *Protocol) handler(msg *packet.HandshakeMessage, pkt []byte) error {
	channel, ok := p.channels[msg.GIK.GroupId]	// we need to identify the group before verifying the message
	if !ok {
		channel = nil
	}
	if channel != nil {	// if a group channel doesn't exist the message will be simply ignored or will cause an error so no need to verify
		if channel.epoch != 0 && int(msg.PriorEpoch) != channel.epoch + 1 {
			return ErrEpochOutOfSync
		}
	}

	init := false
	switch msg.Type {
	case packet.HandshakeNone:	// to return the GroupInitKey in Handshake
		// no-op
	case packet.HandshakeInit:
		// no-op
	case packet.HandshakeUserAdd:
		if channel == nil {
			return ErrGroupNotFound
		}
		addPath := msg.Data.(*packet.UserAdd).Path
		if bytes.Equal(msg.IdentityKey, p.sig.PublicKey()) {
			// just double-check the path and do nothing
			path := channel.state.GetSelfPath()
			if len(path) != len(addPath) {
				return ErrInconsistentPath
			}
			for i, p := range addPath {
				if !bytes.Equal(p, path[i]) {
					return ErrInconsistentPath
				}
			}
		} else {
			uid, err := p.auth.Lookup(msg.IdentityKey)	// since no UIK, verify the identity key in the message instead
			if err != nil {
				return err
			}
			// verify the Merkle proof against a temporary updated copy
			ng, err := channel.state.Copy()
			idx, err := ng.AddPath(addPath, msg.IdentityKey)
			if err != nil {
				return err
			}
			if err := verifyProof(ng, msg); err != nil {
				return err
			}
			// now update the state
			channel.state.AddPath(addPath, msg.IdentityKey)
			channel.peers[uid] = idx
		}
		init = true
	case packet.HandshakeGroupAdd:
		uik := msg.Data.(*packet.GroupAdd).UIK
		uid, err := p.verifyUIK(uik)
		if err != nil {
			return err
		}
		if bytes.Equal(uik.IdentityKey, p.sig.PublicKey()) {
			// someone has added me
			if channel != nil {
				// someone has added me again to an existing group??
				// since there's no protocol to delete groups take this to create a new group with the same group ID
				log.Printf("handshake: [%s] %d has added me again to an existing group... ignore it", p.self, msg.SignerIndex)
			} else {
				channel, err = p.newGroupChannelWithGIK(msg.GIK)
				if err != nil {
					return err
				}
				// !!! We can't verify the Merkle proof here !!!
				if err := channel.initializeWithUIK(uik); err != nil {	// add myself
					return err
				}
			}

			// should renew the UIK and register it to the directory service
			if _, err := p.generateUIK(); err != nil {
				return err
			}
		} else {
			if channel == nil {
				// not my group or not yet received the GroupAdd for myself
				return nil	// just ignore
			}
			if err := verifyProof(channel.state, msg); err != nil {
				return err
			}
			idx, err := channel.state.AddUser(uik)
			if err != nil {
				return err
			}
			channel.peers[uid] = idx
		}
		init = true
	case packet.HandshakeUpdate:
		if channel == nil {
			return ErrGroupNotFound
		}
		if err := verifyProof(channel.state, msg); err != nil {
			return ErrMerkleProofVerificationFailure
		}
		path := msg.Data.(*packet.Update).Path
		channel.state.UpdatePath(int(msg.SignerIndex), path)
	case packet.HandshakeDelete:
		if channel == nil {
			if bytes.Equal(msg.IdentityKey, p.sig.PublicKey()) {
				return nil	// sent by self and the channel already has been closed
			}
			return ErrGroupNotFound
		}
		if err := verifyProof(channel.state, msg); err != nil {
			return err
		}
		del := msg.Data.(*packet.Delete)
		if int(del.Index) == channel.peers[p.self] {
			channel.Close()		// delete me
		} else {
			channel.state.DeletePath(int(del.Index), del.Path)
		}
	default:
		return ErrUnknownHandshakeProtocol
	}
	if err := channel.state.KeyScheduling(init, pkt); err != nil {
		return err
	}
	// someone initiated the message is responsible to update GIK
	if bytes.Equal(msg.IdentityKey, p.sig.PublicKey()) {
		gik, err := channel.state.ConstructGroupInitKey()
		if err != nil {
			return err
		}
		p.directory.RegisterGIK(gik.GroupId, gik)
	}
	channel.epoch = int(msg.PriorEpoch)
	return nil
}

func verifyProof(g *GroupState, msg *packet.HandshakeMessage) error {
	if !g.VerifyProof(msg.IdentityKey, msg.MerkleProof, int(msg.SignerIndex)) {
		fmt.Printf("VerifyProof failed: Merkle Tree: %d\n", g.self)
		g.merkleTree.TraceTree(func(level int, size int, value interface{}) {
			if value == nil {
				fmt.Printf("[%d] nil (%d)\n", level, size)
			} else {
				fmt.Printf("[%d] %x (%d)\n", level, value, size)
			}
		})
		fmt.Printf("Proof: SignerIndex = %d\n", msg.SignerIndex)
		for i := 0; i < len(msg.MerkleProof); i++ {
			fmt.Printf(" [%d] %x\n", i, msg.MerkleProof[i])
		}
		
		return ErrMerkleProofVerificationFailure
	}
	return nil
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

func (c *GroupChannel) marshal(g *GroupState, data interface{}) ([]byte, error) {
	var msg packet.HandshakeMessage
	sig := c.protocol.sig
	
	switch data.(type) {
	case *packet.GroupAdd:
		msg.Type = packet.HandshakeGroupAdd
	case *packet.UserAdd:
		msg.Type = packet.HandshakeUserAdd
	case *packet.Update:
		msg.Type = packet.HandshakeUpdate
	case *packet.Delete:
		msg.Type = packet.HandshakeDelete
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
	msg.IdentityKey = sig.PublicKey()
	msg.SignatureAlgorithm = sig.Algorithm()

	return packet.MarshalHandshake(&msg, sig)
}
