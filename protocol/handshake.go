// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package protocol

import (
	"io"
	"bytes"
	"errors"
	"log"
	"sync"

	"github.com/r2ishiguro/mls"
	"github.com/r2ishiguro/mls/ds"
	"github.com/r2ishiguro/mls/crypto"
	"github.com/r2ishiguro/mls/auth"
	"github.com/r2ishiguro/mls/packet"

	"fmt"
)

var (
	ErrKeyNotFound = errors.New("key not found")
	ErrUserNotFound = errors.New("user not found")
	ErrGroupNotFound = errors.New("group not found")
	ErrAuthFailure = errors.New("authentication failed")
	ErrVerificationFailure = errors.New("verification failed")
	ErrInconsistentPath = errors.New("inconsistent path")
	ErrUnknownHandshakeProtocol = errors.New("unknown protocol")
	ErrMerkleProof = errors.New("something wrong with the merkle tree")
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
	mutex sync.Mutex
}

type GroupChannel struct {
	gid string
	state *GroupState
	dh crypto.GroupOperation	// corresponding to the cipher suite
	uids map[string]int		// map of uid(string) to a leaf index
	message *Message
	protocol *Protocol
	epoch int
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
	return p.newGroupChannel(gid, cipher, nil, p.uik)
}

// create a new GroupChannel with a given GroupInitKey
func (p *Protocol) NewGroupChannelWithGIK(gik *mls.GroupInitKey, uik *mls.UserInitKey) (*GroupChannel, error) {
	return p.newGroupChannel(gik.GroupId, gik.Cipher, gik, uik)
}

func (p *Protocol) newGroupChannel(gid string, cipher mls.CipherSuite, gik *mls.GroupInitKey, uik *mls.UserInitKey) (*GroupChannel, error) {
	privKey := p.getPrivateKey(uik, cipher)
	if privKey == nil {
		return nil, ErrKeyNotFound
	}
	channel := &GroupChannel{gid: gid, protocol: p}
	// initialize the group state with the self key
	channel.state = NewGroupState(gid, p.sig)
	var idx int
	var err error
	if gik != nil {
		idx, err = channel.state.InitializeWithGIK(gik, privKey, uik.IdentityKey)
	} else {
		idx, err = channel.state.Initialize(cipher, privKey, uik.IdentityKey /* should be the same as p.sig.PublicKey() */)
	}
	if err != nil {
		return nil, err
	}
	channel.uids = make(map[string]int)
	channel.uids[p.self] = idx
	p.channels[gid] = channel
	return channel, nil
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
	idx, ok := c.uids[member]
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
	for uid, _ := range c.uids {
		res = append(res, uid)
	}
	return res
}

func (c *GroupChannel) Close() {
	if c.message != nil {
		c.message.Close()
	}
	delete(c.protocol.channels, c.gid)
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

	// should renew the UIK and register it to the directory service
	uik, err := p.generateUIK()
	if err != nil {
		return nil, err
	}

	channel, err := p.NewGroupChannelWithGIK(gik, uik)
	if err != nil {
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

func (p *Protocol) Close() {
	for _, c := range p.channels {
		c.Close()
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
			fmt.Printf("handshake: [%s] epoch mismatch %d vs %d\n", p.self, msg.PriorEpoch, channel.epoch + 1)
			return ErrVerificationFailure
		}
		// the signature of HandshakeMessage has been verified already
		if !bytes.Equal(msg.IdentityKey, p.sig.PublicKey()) && !channel.state.VerifyProof(msg.IdentityKey, msg.MerkleProof, int(msg.SignerIndex)) {
			fmt.Printf("handshake: VerifyProof failed: %x\n", msg.MerkleProof)
			channel.state.merkleTree.TraceTree(func(level int, size int, value interface{}) {
				fmt.Printf("[%d] %x (%d)\n", level, value.([]byte), size)
			})
			return ErrVerificationFailure
		}
		fmt.Printf("handshake: [%s] got a message (%d) from %d\n", p.self, msg.PriorEpoch, msg.SignerIndex)
		channel.epoch = int(msg.PriorEpoch)
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
			// just check the path and do nothing
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
			uid, err := p.auth.Lookup(msg.IdentityKey)
			if err != nil {
				return err
			}
			idx, err := channel.state.AddPath(addPath, msg.IdentityKey)
			if err != nil {
				return err
			}
			channel.uids[uid] = idx
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
				channel, err = p.NewGroupChannelWithGIK(msg.GIK, uik)
				if err != nil {
					return err
				}
				channel.epoch = int(msg.PriorEpoch)
				fmt.Printf("handshake: [%s] init for \"%s\", epoch = %d, path = %x, size = %d\n", p.self, msg.GIK.GroupId, msg.PriorEpoch, msg.GIK.MerkleFrontier, msg.GIK.GroupSize)
			}

			// should renew the UIK and register it to the directory service
//			if _, err := p.generateUIK(); err != nil {
//				return err
//			}
		} else {
			if channel == nil {
				// not my group or not yet received the GroupAdd to itself above
				return nil	// just ignore
			}
			idx, err := channel.state.AddUser(uik)
			if err != nil {
				return err
			}
			channel.uids[uid] = idx
		}
		if uid == p.self {	// this message has been made by myself
			// anyone who did GroupAdd is responsible for updating the GroupInitKey
			p.directory.RegisterGIK(msg.GIK.GroupId, msg.GIK)
		}
		init = true
	case packet.HandshakeUpdate:
		if channel == nil {
			return ErrGroupNotFound
		}
		path := msg.Data.(*packet.Update).Path
		channel.state.UpdatePath(path)
	case packet.HandshakeDelete:
		if channel == nil {
			return ErrGroupNotFound
		}
		del := msg.Data.(*packet.Delete)
		if int(del.Index) == channel.uids[p.self] {
			channel.Close()		// delete me
		} else {
			channel.state.DeletePath(del.Path)
		}
	default:
		return ErrUnknownHandshakeProtocol
	}
	if err := channel.state.KeyScheduling(init, pkt); err != nil {
		return err
	}
	return nil
}

func (c *GroupChannel) verifyHandshakeMessage(msg *packet.HandshakeMessage, pkt []byte) error {
	// first check the merkle proof
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
	return ks[cipher]
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

	idx, proof := g.Proof()
	if idx < 0 {
		return nil, ErrMerkleProof
	}

	msg.SignerIndex = uint32(idx)
	msg.MerkleProof = proof
	msg.IdentityKey = sig.PublicKey()
	msg.SignatureAlgorithm = sig.Algorithm()

	return packet.MarshalHandshake(&msg, sig)
}
