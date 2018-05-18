// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package ds

import (
	"testing"
	"io"
	"fmt"
	"time"

	"github.com/r2ishiguro/mls"
	"github.com/r2ishiguro/mls/packet"
)

const (
	addr = "localhost:9897"
	nclients = 10
)

type testClient struct {
	epoch int
	ds *DeliveryService
	sig *mls.Signature
	num int
}

func TestBroadcast(t *testing.T) {
	b, err := startBroadcaster(":9897")
	if err != nil {
		t.Fatal(err)
	}

	var clients []*testClient
	for n := 0; n < nclients; n++ {
		ds := NewClient(addr)
		// we need at least the signature to marshal/unmarshal the message
		sig, err := mls.NewSignature(mls.SignatureECDSA)
		if err != nil {
			t.Fatal(err)
		}
		pub, priv, err := sig.Generate()
		if err != nil {
			t.Fatal(err)
		}
		sig.Initialize(pub, priv)
		c := &testClient{0, ds, sig, n}
		go func(ds *DeliveryService, c *testClient) {
			err := ds.Run(c)
			if err != nil {
				t.Error(err)
			}
		}(ds, c)
		time.Sleep(100 * time.Millisecond)	// make sure clients[i].conn is established before client[j].conn when i < j
		clients = append(clients, c)
	}

	// wait for all clients to be ready
	for retry := 10; retry >= 0; retry-- {
		n := 0
		for _, c := range clients {
			if c.ds.conn != nil {
				n++
			}
		}
		if n == len(clients) {
			break
		}
		time.Sleep(100 * time.Millisecond)
		if retry == 0 {
			t.Fatalf("clients not ready")
		}
	}

	// single client, synchronized
	c := clients[0]
	epoch := 0
	for ntests := 10; ntests > 0; ntests-- {
		msg := &packet.HandshakeMessage{
			Type: packet.HandshakeNone,
			PriorEpoch: uint32(epoch),
			GIK: &mls.GroupInitKey{},
			IdentityKey: c.sig.PublicKey(),
			SignatureAlgorithm: c.sig.Algorithm(),
		}
		pkt, err := packet.MarshalHandshake(msg, c.sig)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("sending %d\n", epoch)
		if err := c.ds.Send(pkt); err != nil {
			t.Fatal(err)
		}
		epoch++
	}
	time.Sleep(1 * time.Second)

	// tearing down
	for _, c := range clients {
		c.ds.Close()
	}
	b.stop()
}

func (c *testClient) Handler(r io.Reader) error {
	msg, _, err := packet.UnmarshalHandshake(r)
	if err != nil {
		if !isEOF(err) {
			fmt.Printf("Unmarshal failed [%d]: %s\n", c.num, err)
		}
		return err
	}
	fmt.Printf("Handler [%d]: received: epoch = %d\n", c.num, msg.PriorEpoch)

	if c.epoch != 0 && int(msg.PriorEpoch) != c.epoch + 1 {
		return fmt.Errorf("[%d] epoch mismatch: %d vs %d", c.num, msg.PriorEpoch, c.epoch)
	}
	c.epoch = int(msg.PriorEpoch)
	return nil
}
