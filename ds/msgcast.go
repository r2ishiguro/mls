// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package ds

import (
	"net"
	"io"
	"sync"
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
)

const bufSize = 1024

var (
	ErrNoMoreChannel = errors.New("no more channels")
)

//
// client
//
type MessageService struct {
	conn net.Conn
	rw *bufio.ReadWriter
}

func NewMessageService(msgAddr string, gid string) (*MessageService, error) {
	conn, err := net.Dial("tcp", msgAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(gid)); err != nil {
		return nil, err
	}
	res, err := readUp(conn)
	if err != nil {
		return nil, err
	}
	chAddr := string(res)
	if chAddr == "" {
		return nil, ErrNoMoreChannel
	}

	chConn, err := net.Dial("tcp", chAddr)
	if err != nil {
		return nil, err
	}
	return &MessageService{
		conn: chConn,
		rw: bufio.NewReadWriter(bufio.NewReader(chConn), bufio.NewWriter(chConn)),
	}, nil
}

func (m *MessageService) Send(data []byte) error {
	w := m.rw.Writer
	if err := binary.Write(w, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	return nil
}

func (m *MessageService) Receive() ([]byte, error) {
	r := m.rw.Reader
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		if isEOF(err) {
			err = io.EOF
		}
		return nil, err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		if isEOF(err) {
			err = io.EOF
		}
		return nil, err
	}
	return buf, nil
}

func (m *MessageService) Close() {
	m.conn.Close()
}

//
// server
//
type msgcast struct {
	listener net.Listener
	portRange [2]int
	port int
	channels map[string]*msgChannel
}

type msgChannel struct {
	listener net.Listener
	clients map[string]net.Conn
	mutex sync.Mutex
}

func startMessageCast(addr string, portRange [2]int) (*msgcast, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &msgcast{
		listener: l,
		portRange: portRange,
		port: portRange[0],
		channels: make(map[string]*msgChannel),
	}
	go func(s *msgcast) {
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				break
			}
			pkt, err := readUp(conn)
			if err == nil {
				gid := string(pkt)
				channel, ok := s.channels[gid]
				if !ok {
					channel = nil
					if s.port <= s.portRange[1] {
						channel, err = newMessageChannel(s.port)
						if err == nil {
							s.port++
							s.channels[gid] = channel
						}
					}
				}
				if channel != nil {
					conn.Write([]byte(channel.addr()))
				} else {
					conn.Write([]byte(""))
				}
			}
			conn.Close()
		}
	}(s)
	return s, nil
}

func (s *msgcast) stop() {
	s.listener.Close()
}

func newMessageChannel(port int) (*msgChannel, error) {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	c := &msgChannel{
		listener: l,
		clients: make(map[string]net.Conn),
	}
	go func(c *msgChannel) {
		for {
			conn, err := c.listener.Accept()
			if err != nil {
				if !isEOF(err) {
					log.Printf("msgcast: %s", err)
				}
				break
			}
			addr := conn.RemoteAddr()
			c.mutex.Lock()
			c.clients[addr.String()] = c.newClient(conn)
			c.mutex.Unlock()
		}
	}(c)
	return c, nil
}

func (c *msgChannel) addr() string {
	return c.listener.Addr().String()
}

func (c *msgChannel) close() {
	c.listener.Close()
	for _, client := range c.clients {
		client.Close()
	}
	c.clients = make(map[string]net.Conn)
}

func (c *msgChannel) newClient(conn net.Conn) net.Conn {
	go func(conn net.Conn) {
		for {
			pkt, err := readUp(conn)
			if err != nil {
				break
			}
			c.mutex.Lock()
			for addr, client := range c.clients {
				// this doesn't gurantee either in-order delivery or consisent ordering
				go func(addr string, client net.Conn, pkt []byte) {
					if _, err := client.Write(pkt); err != nil {
						client.Close()
						c.mutex.Lock()
						delete(c.clients, addr)
						c.mutex.Unlock()
					}
				}(addr, client, pkt)
			}
			c.mutex.Unlock()
		}
		conn.Close()
	}(conn)
	return conn
}

func readUp(r io.Reader) ([]byte, error) {
	buf := make([]byte, bufSize)
	n, err := r.Read(buf)
	if err != nil {
		if isEOF(err) {
			err = io.EOF
		}
		return nil, err
	}
	if n == 0 {
		return nil, io.EOF
	}
	return buf[:n], nil
}
