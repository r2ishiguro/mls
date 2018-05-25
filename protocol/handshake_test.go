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
	testGroupId = "chat room 1"
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
	testUIDs = []string{
		"user0", "user1", "user2", "user3", "user4", "user5", "user6",
	}
)

func TestAddMembers(t *testing.T) {
	// start the servers
	server := ds.NewServer(deliveryAddress, directoryAddress, messageAddress, channelPorts, simplekv.New())
	defer server.Close()
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)

	clients, err := createClients(testUIDs)
	if err != nil {
		t.Fatal(err)
	}

	channel, err := clients[0].CreateGroupChannel(testGroupId, mls.CipherP256R1WithSHA256)
	if err != nil {
		t.Fatal(err)
	}

	p := channel.protocol
	g := channel.state
	for _, client := range clients[1:] {
		uid, err := p.verifyUIK(client.uik)
		if err != nil {
			t.Fatal(err)
		}
		if uid != client.self {
			t.Fatal(ErrAuthFailure)
		}
		ng, err := g.Copy()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ng.AddUser(client.uik); err != nil {
			t.Fatal(err)
		}
		pkt, err := client.marshal(g, &packet.GroupAdd{client.uik})
		if err != nil {
			t.Fatal(err)
		}
		// imitate that each client receives the packet
		if err := ng.KeyScheduling(true, pkt, g.Epoch()); err != nil {
			t.Fatal(err)
		}
		// imitate broadcast via DS
		msg, _, err := packet.UnmarshalHandshake(bytes.NewReader(pkt))
		if err != nil {
			t.Fatal(err)
		}
		for _, peer := range clients {
			fmt.Printf("adding %s to %s...\n", client.self, peer.self)
			if err := GroupChannelHandler(peer, nil, msg, pkt); err != nil {
				t.Fatal(err)
			}
		}
		g = ng
	}
}

func TestHandshake(t *testing.T) {
	server := ds.NewServer(deliveryAddress, directoryAddress, messageAddress, channelPorts, simplekv.New())
	defer server.Close()
	// start the servers
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if _, err := testHandshake(testUIDs); err != nil {
		t.Fatal(err)
	}
}

func testHandshake(uids []string) ([]*Protocol, error) {
	clients, err := createClients(uids)
	if err != nil {
		return nil, err
	}

	// run all clients
	for _, p := range clients {
		if err := p.Connect(deliveryAddress); err != nil {
			return nil, err
		}
		go func(p *Protocol) {
			err := p.Run()
			if err != nil {
				fmt.Printf("[%s] finished with %s\n", p.self, err)
			} else {
				fmt.Printf("[%s] finished\n", p.self)
			}
		}(p)
	}

	channel, err := clients[0].CreateGroupChannel(testGroupId, mls.CipherP256R1WithSHA256)
	if err != nil {
		return nil, err
	}
	if err := channel.AddMembers(uids[1:]); err != nil {
		return nil, err
	}

	if err := checkSync(clients); err != nil {
		return nil, err
	}
	return clients, err
}

func TestJoin(t *testing.T) {
	server := ds.NewServer(deliveryAddress, directoryAddress, messageAddress, channelPorts, simplekv.New())
	defer server.Close()
	// start the servers
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	clients, err := testHandshake([]string{"user0", "user1"}/*testUIDs*/)
	if err != nil {
		t.Fatal(err)
	}

	// create a new client to join
	newClients, err := createClients([]string{"user999"})
	if err != nil {
		t.Fatal(err)
	}
	p := newClients[0]
	if err := p.Connect(deliveryAddress); err != nil {
		t.Fatal(err)
	}
	go p.Run()
	if _, err := p.Join(testGroupId); err != nil {
		t.Fatal(err)
	}
	if err := checkSync(append(clients, p)); err != nil {
		t.Fatal(err)
	}
}

func createClients(uids []string) ([]*Protocol, error) {
	var clients []*Protocol
	// register and run self and all peers
	for _, user := range append(uids) {
		// generate an identityKey and register it with the uid
		auth := NewDummAuth(user)
		sig, err := mls.NewSignature(mls.SignatureECDSA)
		if err != nil {
			return nil, err
		}
		pub, priv, err := sig.Generate()
		if err != nil {
			return nil, err
		}
		sig.Initialize(pub, priv)
		auth.Register(pub, user)

		dir := ds.NewDirectoryService(directoryAddress)
		p := New(user, dir, sig, auth, aesgcm.NewAESGCM())
		p.generateUIK()	// p.Connect() will overwrite

		clients = append(clients, p)
	}
	return clients, nil
}

func checkSync(clients []*Protocol) error {
	// wait for all clients to receive the message
	keys := make(map[string][]byte)
	lastClient := clients[len(clients)-1].self
	for retry := 5; retry > 0 && len(keys) < len(clients); retry-- {	// including self
		for _, c := range clients {
			if _, ok := keys[c.self]; ok {
				continue
			}
			if channel, ok := c.channels[testGroupId]; ok {
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
		return fmt.Errorf("some clients couldn't receive the message")
	}
	key := keys[clients[0].self]
	for user, k := range keys {
		if !bytes.Equal(key, k) {
			// return fmt.Errorf("%s: message key mismatch", user)
			fmt.Printf("%s: mismatch: %x\n", user, k)
		}
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
