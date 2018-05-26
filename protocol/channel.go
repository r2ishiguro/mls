// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package protocol

import (
	"bytes"
	"log"
	"io"
	"fmt"

	"github.com/r2ishiguro/mls"
	"github.com/r2ishiguro/mls/packet"
)

type GroupChannel struct {
	gid string
	peers map[string]int		// map of UID to the leaf index -- just for Delete() with UID
	state *GroupState
	message *Message
	protocol *Protocol
}

func NewGroupChannel(p *Protocol, gid string, cipher mls.CipherSuite) (*GroupChannel, error) {
	g, err := NewGroupState(gid, cipher, p.sig)
	if err != nil {
		return nil, err
	}
	channel := &GroupChannel{
		gid: gid,
		protocol: p,
		state: g,
		peers: make(map[string]int),
	}
	return channel, nil
}

func NewGroupChannelWithGIK(p *Protocol, gik *mls.GroupInitKey) (*GroupChannel, error) {
	g, err := NewGroupStateWithGIK(gik, p.sig)
	if err != nil {
		return nil, err
	}
	channel := &GroupChannel{
		gid: gik.GroupId,
		protocol: p,
		state: g,
		peers: make(map[string]int),
	}
	return channel, nil
}

func (c *GroupChannel) Initialize(privKey []byte, identityKey []byte) error {
	idx, err := c.state.AddSelf(privKey, identityKey)
	if err != nil {
		return err
	}
	c.peers[c.protocol.self] = idx
	return nil
}

func (c *GroupChannel) RegisterGIK() error {
	gik, err := c.state.ConstructGroupInitKey()
	if err != nil {
		return err
	}
	if err := c.protocol.directory.RegisterGIK(gik.GroupId, gik); err != nil {
		return err
	}
	return err
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
		pkt, err := p.marshal(g, &packet.GroupAdd{uik})
		if err != nil {
			return err
		}
		// imitate that each client receives the packet
		if err := ng.KeyScheduling(true, pkt, g.Epoch()); err != nil {
			return err
		}
		if err := p.ds.Send(pkt); err != nil {
			return err
		}
		g = ng
	}
	return nil
}

func (c *GroupChannel) Join() error {
	path := c.state.GetSelfPath()
	pkt, err := c.protocol.marshal(c.state, &packet.UserAdd{path})	// use the updated GIK
	if err != nil {
		return err
	}
	return c.protocol.ds.Send(pkt)
}

// update the key pair of self
func (c *GroupChannel) Update(privKey []byte) error {
	ng, err := c.state.Copy()
	if err != nil {
		return err
	}
	if err := ng.UpdateSelf(privKey); err != nil {
		return err
	}
	path := ng.GetSelfPath()
	pkt, err := c.protocol.marshal(c.state, &packet.Update{path})
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
	pkt, err := c.protocol.marshal(c.state, &packet.Delete{uint32(idx), path})
	if err != nil {
		return err
	}
	if err := c.protocol.ds.Send(pkt); err != nil {
		return err
	}
	return nil
}

func (c *GroupChannel) None() error {
	pkt, err := c.protocol.marshal(c.state, &packet.None{})
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

func (c *GroupChannel) NewMessage(msgAddr string) (*Message, error) {
	msg, err := NewMessage(msgAddr, c.gid, c.protocol, c.state)
	if err != nil {
		return nil, err
	}
	c.message = msg
	return msg, nil
}

func (c *GroupChannel) Close() {
	if c.message != nil {
		c.message.Close()
		c.message = nil
	}
	c.Delete(c.protocol.self)		// then broadcast the Delete message too all but self
}

func GroupChannelHandler(p *Protocol, channel *GroupChannel, msg *packet.HandshakeMessage, pkt []byte) error {
	init := false
	eof := false
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
			channel.state.CopyBack(ng)
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
				// !!! We can't verify the Merkle proof here !!!
				channel, err = p.CreateGroupChannelWithGIK(msg.GIK, uik)
				if err != nil {
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
		if err := channel.state.UpdatePath(int(msg.SignerIndex), path); err != nil {
			return err
		}
	case packet.HandshakeDelete:
		if channel == nil {
			return ErrGroupNotFound
		}
		if err := verifyProof(channel.state, msg); err != nil {
			return err
		}
		del := msg.Data.(*packet.Delete)
		if int(del.Index) == channel.peers[p.self] {
			if channel.message != nil {
				channel.message.Close()
			}
			eof = true
		} else {
			if err := channel.state.DeletePath(int(del.Index), del.Path); err != nil {
				return err
			}
		}
	default:
		return ErrUnknownHandshakeProtocol
	}
	if err := channel.state.KeyScheduling(init, pkt, msg.PriorEpoch); err != nil {
		return err
	}
	// someone who has initiated the message is responsible to update GIK
	if bytes.Equal(msg.IdentityKey, p.sig.PublicKey()) {
		if err := channel.RegisterGIK(); err != nil {
			return err
		}
	}
	if eof {
		return io.EOF
	}
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
		root, path := g.merkleTree.Calculate(int(msg.SignerIndex), msg.IdentityKey)
		fmt.Printf("Root: %x\n", root)
		for i := 0; i < len(path); i++ {
			fmt.Printf("  [%d] %x\n", i, path[i].([]byte))
		}
		
		return ErrMerkleProofVerificationFailure
	}
	return nil
}
