// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package ds

import (
	"net"
	"sync"
	"log"
	"time"

	"github.com/r2ishiguro/mls/packet"
)

//
// Group Channel (Broadcaster)
//
type broadcaster struct {
	l net.Listener
	clients map[string]*client
	epoch uint32
	ch chan(*broadcastMessage)
	mutex sync.Mutex
}

type broadcastMessage struct {
	msg *packet.HandshakeMessage
	pkt []byte
}

type client struct {
	conn net.Conn
	ch chan([]byte)
	addr string
}

const (
	maxConnections = 100 /* 2 << 16 */
	queueSize = 100
	broadcastTimeout = 10
)

func startBroadcaster(addr string) (*broadcaster, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &broadcaster{
		l: l,
		clients: make(map[string]*client),
		epoch: 0,
		ch: make(chan *broadcastMessage, maxConnections),
	}
	go s.listener()
	go s.run()
	return s, nil
}

func (s *broadcaster) stop() {
	s.l.Close()
	s.mutex.Lock()
	for _, c := range s.clients {	// since the listner has been already closed s.clients should be safe to get accessed without mutex
		if c.conn != nil {
			c.conn.Close()
		}
	}
	s.mutex.Unlock()
}

func (s *broadcaster) listener() {
	for {
		conn, err := s.l.Accept()
		if err != nil {
			if !isEOF(err) {
				log.Printf("broadcaster: Accept() failed: %s", err)
			}
			break
		}
		addr := conn.RemoteAddr()
		client := s.newClient(conn)
		s.mutex.Lock()
		s.clients[addr.String()] = client
		s.mutex.Unlock()
	}
}

func (s *broadcaster) run() {
	for {
		bm, ok := <- s.ch
		if !ok {
			break
		}
		s.mutex.Lock()
		if s.epoch == 0 || bm.msg.PriorEpoch == s.epoch + 1 {
			s.epoch = bm.msg.PriorEpoch
			s.broadcast(bm.pkt)
		} else {
			log.Printf("broadcast: %d != %d", bm.msg.PriorEpoch, s.epoch + 1)
		}
		s.mutex.Unlock()
	}
}

func (s *broadcaster) broadcast(pkt []byte) {
	for _, client := range s.clients {
		if len(client.ch) >= cap(client.ch) {
			continue
		}
		client.ch <- pkt
	}
}

func (s *broadcaster) newClient(conn net.Conn) *client {
	c := &client{
		conn: conn,
		ch: make(chan []byte, queueSize),
		addr: conn.RemoteAddr().String(),
	}
	go func(c *client) {
		for {
			msg, pkt, err := packet.UnmarshalHandshake(c.conn)
			if err != nil {
				if !isEOF(err) {
					log.Printf("broadcast: [%s] Unmarshal failed: %s", c.addr, err)
				}
				break
			}
			s.ch <- &broadcastMessage{msg, pkt}
		}
		s.closeClient(c)
	}(c)
	go func(c *client) {
		for {
			pkt, ok := <- c.ch
			if !ok {
				break
			}
			c.conn.SetWriteDeadline(time.Now().Add(broadcastTimeout * time.Second))
			if _, err := c.conn.Write(pkt); err != nil {
				log.Printf("broadcast: [%s] Write() failed: %s", c.addr, err)
				break
			}
		}
		s.closeClient(c)
	}(c)
	return c
}

func (s *broadcaster) closeClient(c *client) {
	s.mutex.Lock()
	delete(s.clients, c.addr)
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	if c.ch != nil {
		close(c.ch)
		c.ch = nil
	}
	s.mutex.Unlock()
}
