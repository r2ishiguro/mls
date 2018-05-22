// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package protocol

import (
	"testing"
	"bytes"
	"time"
	"io"
	"fmt"
)

const (
	testMessage = "abc"
)

func TestMessage(t *testing.T) {
	server, channel, err := testHandshake()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	m, err := channel.NewMessage(messageAddress)
	if err != nil {
		t.Fatal(err)
	}
	go func(m *Message) {
		for {
			msg, uid, err := m.Receive()
			if err != nil {
				if err != io.EOF {
					t.Fatal(err)
				}
				break
			}
			fmt.Printf("%s: %s\n", uid, string(msg))
			if !bytes.Equal(msg, []byte(testMessage)) {
				t.Fatalf("mismatch %s vs %s", string(msg), testMessage)
			}
		}
	}(m)
	if err := m.Send([]byte(testMessage)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1 * time.Second)
	m.Close()
}
