// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package ds

import (
	"testing"
	"net"
	"fmt"
	"time"
	"strings"
	"io"
	"bufio"
)

const (
	testAddr = "localhost:9897"
	numTests = 10
	bufSize = 1024*1024
)

type Client struct {
	conn net.Conn
	id int
}

func TestNet(t *testing.T) {
	l, err := net.Listen("tcp", testAddr)
	if err != nil {
		t.Fatal(err)
	}
	go func(l net.Listener) {
		var conns []net.Conn
		for {
			conn, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			fmt.Printf("accepted %s\n", conn.RemoteAddr().String())
			conns = append(conns, conn)
			go func(conn net.Conn) {
				buf := make([]byte, bufSize)
				bio := bufio.NewReader(conn)
				for {
					n, err := io.ReadFull(bio, buf)
					if err != nil {
						if err == io.EOF {
							break
						}
						t.Fatalf("server: Read error: %s", err)
					}
					if n != len(buf) {
						t.Errorf("server: got %d bytes", n)
					}
					fmt.Printf("server: got %d\n", buf[0])

					for _, w := range conns {
						n, err = w.Write(buf)
						if err != nil {
							t.Fatalf("server: conn.Write error: %s", err)
						}
						if n != len(buf) {
							t.Errorf("server: sent %d bytes", n)
						}
					}
				}
			}(conn)
		}
	}(l)
	time.Sleep(1 * time.Second)

	var clients []Client
	for nclients := 0; nclients < 10; nclients++ {
		conn, err := net.Dial("tcp", testAddr)
		if err != nil {
			t.Fatal(err)
		}
		c := Client{conn, nclients}
		go func(c *Client) {
			var epoch = 0
			buf := make([]byte, bufSize)
			bio := bufio.NewReader(c.conn)
			for {
				n, err := io.ReadFull(bio, buf)
				if err != nil {
					if err == io.EOF {
						break
					}
					// ssrly!?
					str := err.Error()
					if strings.Contains(str, "use of closed network connection") {
						break
					}
					t.Fatalf("client: conn.Read error: %s", err)
				}
				if n != len(buf) {
					t.Errorf("client: got %d bytes", n)
				}
				fmt.Printf("client[%d]: got %d\n", c.id, buf[0])
				if epoch != int(buf[0]) {
					t.Errorf("client[%d]: got %d, have %d\n", c.id, buf[0], epoch)
				}
				epoch++
			}
			if epoch != numTests {
				t.Errorf("client[%d]: epoch = %d", c.id, epoch)
			}
		}(&c)
		clients = append(clients, c)
	}
	time.Sleep(100 * time.Millisecond)

	c := clients[0]
	buf := make([]byte, bufSize)
	for i := 0; i < numTests; i++ {
		buf[0] = byte(i)
		n, err := c.conn.Write(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n != len(buf) {
			t.Errorf("sent %d bytes", n)
		}
	}
	time.Sleep(1 * time.Second)
	for _, c := range clients {
		c.conn.Close()
	}
}
