// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package protocol

import (
	"testing"
	"bytes"
	"time"
	"io"
	"fmt"

	"github.com/r2ishiguro/mls/ds"
	"github.com/r2ishiguro/mls/ds/keystore/simplekv"
)

const (
	testMessage = "abc"
)

func TestMessage(t *testing.T) {
	server := ds.NewServer(deliveryAddress, directoryAddress, messageAddress, channelPorts, simplekv.New())
	defer server.Close()
	// start the servers
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	clients, err := testHandshake(testUIDs)
	if err != nil {
		t.Fatal(err)
	}

	var messages []*Message
	for _, client := range clients {
		channel := client.channels[testGroupId]
		m, err := channel.NewMessage(messageAddress)
		if err != nil {
			t.Fatal(err)
		}
		go func(p *Protocol, m *Message) {
			for {
				msg, uid, err := m.Receive()
				if err != nil {
					if err != io.EOF {
						t.Fatal(err)
				}
					break
				}
				fmt.Printf("[%s => %s]: %s\n", uid, p.self, string(msg))
				if !bytes.Equal(msg, []byte(testMessage)) {
					t.Fatalf("mismatch %s vs %s", string(msg), testMessage)
				}
			}
		}(client, m)
		messages = append(messages, m)
	}

	for _, m := range messages {
		go func(m *Message) {
			if err := m.Send([]byte(testMessage)); err != nil {
				t.Fatal(err)
			}
		}(m)
	}
	
	time.Sleep(1 * time.Second)
	for _, m := range messages {
		m.Close()
	}
}
