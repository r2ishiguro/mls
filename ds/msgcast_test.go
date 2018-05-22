// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package ds

import (
	"testing"
	"fmt"
	"time"
	"bytes"
	"io"
)

const (
	msgaddr = "localhost:9899"
	startPort = 9900
	endPort = 9999
	testGID = "chat room"
	msgClient = "client"
	testMessage = "abc"
	nservices = 10
	ngroups = 10
)

type messageTest struct {
	m *MessageService
	msg string
}

func TestMessage(t *testing.T) {
	msgcast, err := startMessageCast(msgaddr, [2]int{startPort, endPort})
	if err != nil {
		t.Fatal(err)
	}
	defer msgcast.stop()

	var messageTests []*messageTest
	for i := 0; i < ngroups; i++ {
		gid := fmt.Sprintf("%s %d", testGID, i)
		msg := fmt.Sprintf("%s %d", testMessage, i)
		for j := 0; j < nservices; j++ {
			m, err := NewMessageService(msgaddr, gid)
			if err != nil {
				t.Fatal(err)
			}
			cid := fmt.Sprintf("%s %d", msgClient, j)
			mt := &messageTest{m, msg}
			go func(mt *messageTest) {
				if err := runMessage(cid, mt.m, mt.msg); err != nil {
					t.Fatal(err)
				}
			}(mt)
			messageTests = append(messageTests, mt)
		}
	}
	time.Sleep(1 * time.Second)

	for _, mt := range messageTests {
		if err := mt.m.Send([]byte(mt.msg)); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(1 * time.Second)

	for _, mt := range messageTests {
		mt.m.Close()
	}
}

func runMessage(prompt string, m *MessageService, org string) error {
	for {
		msg, err := m.Receive()
		if err != nil {
			if err != io.EOF {
				return err
			}
			fmt.Printf("%s: EOF\n", prompt)
			return nil
		}
		// it's possible Receve() has recevied multiple messages and returns them into "msg" at once
		fmt.Printf("%s: got %s\n", prompt, string(msg))
		for len(msg) > 0 {
			if !bytes.Equal(msg[:len(org)], []byte(org)) {
				return fmt.Errorf("%s: mismatch: %s vs %s", prompt, msg[:len(org)], org)
			}
			msg = msg[len(org):]
		}
	}
}
