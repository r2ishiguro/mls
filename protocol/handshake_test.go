// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package protocol

import (
	"testing"
	"time"
	"bytes"
	"sync"
	"errors"
	"fmt"

	"github.com/r2ishiguro/mls"
	"github.com/r2ishiguro/mls/ds"
	"github.com/r2ishiguro/mls/ds/keystore/simplekv"
	"github.com/r2ishiguro/mls/packet"
	"github.com/r2ishiguro/mls/crypto/aesgcm"
)

const (
	gid = "chat room 1"
	deliveryAddress = "localhost:9898"
	directoryAddress = "localhost:9899"
	messageAddress = "localhost:9900"
)

var (
	channelPorts = [2]int{9901, 9999}
	ciphers = []mls.CipherSuite{	// it's not guaranteed to generate keys for all ciphers
		mls.CipherX25519WithSHA256,
		mls.CipherP256R1WithSHA256,
	}
	peers = []string{
		"user1", "user2", "user3", "user4", "user5", "user6",
	}
	me = "user0"
)

func TestHandshake(t *testing.T) {
	server, _, err := testHandshake()
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
}

func testHandshake() (*ds.Server, *GroupChannel, error) {
	// start the servers
	server := ds.NewServer(deliveryAddress, directoryAddress, messageAddress, channelPorts, simplekv.New())
	if err := server.Start(); err != nil {
		return nil, nil, err
	}
	time.Sleep(time.Second)

	clients := make(map[string]*Protocol)
	// register and run self and all peers
	for _, user := range append([]string{me}, peers...) {
		// generate an identityKey and register it with the uid
		auth := NewDummAuth(user)
		sig, err := mls.NewSignature(mls.SignatureECDSA)
		if err != nil {
			return nil, nil, err
		}
		pub, priv, err := sig.Generate()
		if err != nil {
			return nil, nil, err
		}
		sig.Initialize(pub, priv)
		auth.Register(pub, user)
		dir := ds.NewDirectoryService(directoryAddress)
		clients[user] = New(user, dir, sig, auth, aesgcm.NewAESGCM())
		if err := clients[user].Connect(deliveryAddress); err != nil {
			return nil, nil, err
		}
		go func(client *Protocol) {
			err := client.Run()
			if err != nil {
				fmt.Printf("[%s] finished with %s\n", client.self, err)
			} else {
				fmt.Printf("[%s] finished\n", client.self)
			}
		}(clients[user])
	}

	self := clients[me]
	channel, err := self.NewGroupChannelWithGID(gid, mls.CipherP256R1WithSHA256)
	if err != nil {
		return nil, nil, err
	}
	if err := channel.AddMembers(peers); err != nil {
		return nil, nil, err
	}

	// wait for all clients to receive the request
	keys := make(map[string][]byte)
	lastClient := len(peers)	// len(peers) + 1
	for retry := 5; retry > 0 && len(keys) < len(clients); retry-- {	// including self
		for _, c := range clients {
			if _, ok := keys[c.self]; ok {
				continue
			}
			if channel, ok := c.channels[gid]; ok {
				if _, ok := channel.peers[lastClient]; ok {
					keys[c.self] = channel.state.MessageKey()
					fmt.Printf("[%s] got a key\n", c.self)
				}
			}
		}
		time.Sleep(time.Second)
	}

	// all clients should have the same tree -- checking the message key should be enough
	if len(keys) < len(clients) {
		return nil, nil, fmt.Errorf("some clients couldn't receive the message")
	}
	for user, k := range keys {
		if !bytes.Equal(keys[me], k) {
			return nil, nil, fmt.Errorf("%s: message key mismatch", user)
		}
	}
	return server, channel, nil
}

func TestAddMembers(t *testing.T) {
	// start the servers
	server := ds.NewServer(deliveryAddress, directoryAddress, messageAddress, channelPorts, simplekv.New())
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	time.Sleep(time.Second)

	clients := make(map[string]*Protocol)
	// register and run self and all peers
	for _, user := range append([]string{me}, peers...) {
		// generate an identityKey and register it with the uid
		auth := NewDummAuth(user)
		sig, err := mls.NewSignature(mls.SignatureECDSA)
		if err != nil {
			t.Fatal(err)
		}
		pub, priv, err := sig.Generate()
		if err != nil {
			t.Fatal(err)
		}
		sig.Initialize(pub, priv)
		auth.Register(pub, user)

		dir := ds.NewDirectoryService(directoryAddress)
		p := New(user, dir, sig, auth, nil)
		// generate a UIK
		uik, privKeys, err := GenerateUserInitKey(defaultCiphers, sig)
		if err != nil {
			t.Fatal(err)
		}
		p.uik = uik
		p.privKeyMap[string(uik.InitKeys[uik.Ciphers[0]])] = privKeys
		clients[user] = p
	}

	self := clients[me]
	channel, err := self.NewGroupChannelWithGID(gid, mls.CipherP256R1WithSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := addMembers(channel, clients); err != nil {
		t.Fatal(err)
	}
}

func addMembers(c *GroupChannel, clients map[string]*Protocol) error {
	p := c.protocol
	g := c.state
	for _, client := range clients {
		uid, err := p.verifyUIK(client.uik)
		if err != nil {
			return err
		}
		if uid != client.self {
			return ErrAuthFailure
		}
		ng, err := g.Copy()
		if err != nil {
			return err
		}
		if _, err := ng.AddUser(client.uik); err != nil {
			return err
		}
		pkt, err := c.marshal(g, &packet.GroupAdd{client.uik})
		if err != nil {
			return err
		}
		// immitate that each client receives the packet
		if err := ng.KeyScheduling(true, pkt); err != nil {
			return err
		}
		// immitate broadcast via DS
		msg, _, err := packet.UnmarshalHandshake(bytes.NewReader(pkt))
		if err != nil {
			return err
		}
		for _, peer := range clients {
			if err := peer.handler(msg, pkt); err != nil {
				return err
			}
		}
		g = ng
	}
	return nil
}

//
// a simple auth service for testing
//
type dummAuth struct {
	mutex sync.Mutex
	self string
}

var dummMap = make(map[string]string)

func NewDummAuth(self string) *dummAuth {
	return &dummAuth{
		self: self,
	}
}

func (a *dummAuth) Lookup(key []byte) (string, error) {
	a.mutex.Lock()
	id, ok := dummMap[string(key)]
	a.mutex.Unlock()
	if !ok {
		return "", errors.New("dummAuth: not found")
	}
	return id, nil
}

func (a *dummAuth) Register(key []byte, id string) error {
	a.mutex.Lock()
	dummMap[string(key)] = id
	a.mutex.Unlock()
	return nil
}

func (a *dummAuth) UId() string {
	return a.self
}
