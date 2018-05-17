// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package ds

import (
	"net"
	"io"

	"github.com/r2ishiguro/mls/ds/keystore"
)

//
// Delivery Service client
//
type DeliveryService struct {
	addr string
	conn net.Conn
	channels map[string]net.Conn
}

type DeliveryServiceClientInterface interface {
	Handler(r io.Reader) error
}

func NewClient(addr string) *DeliveryService {
	return &DeliveryService{
		addr: addr,
		channels: make(map[string]net.Conn),
	}
}

//
// Dilivery Service client
//
func (ds *DeliveryService) Run(client DeliveryServiceClientInterface) error {
	conn, err := net.Dial("tcp", ds.addr)
	if err != nil {
		return err
	}
	ds.conn = conn

	for {
		if err = client.Handler(conn); err != nil {		// let the Handler to handle the error as well
			if err == io.EOF {
				err = nil
			}
			return err
		}
	}
}

func (ds *DeliveryService) Send(data []byte) error {
	_, err := ds.conn.Write(data)
	return err
}

func (ds *DeliveryService) Close() {
	ds.conn.Close()
	ds.conn = nil
}

//
// DS Server
//
type Server struct {
	addr, dirAddr, msgAddr string
	ks keystore.KeyStore
	broadcaster *broadcaster
	directory *directoryServer
	message *msgcast
	msgPortRange [2]int
}

func NewServer(addr, dirAddr, msgAddr string, portRange [2]int, ks keystore.KeyStore) *Server {
	return &Server{
		addr: addr,
		dirAddr: dirAddr,
		msgAddr: msgAddr,
		msgPortRange: portRange,
		ks: ks,
	}
}

func (s *Server) Start() error {
	// start the broadcaster
	b, err := startBroadcaster(s.addr)
	if err != nil {
		return err
	}
	s.broadcaster = b

	// start the directory server
	dir, err := startDirectoryServer(s.dirAddr, s.ks)
	if err != nil {
		return err
	}
	s.directory = dir

	// start the message cast server
	msg, err := startMessageCast(s.msgAddr, s.msgPortRange)
	if err != nil {
		return err
	}
	s.message = msg

	return nil
}

func (s *Server) Close() {
	if s.broadcaster != nil {
		s.broadcaster.stop()
		s.broadcaster = nil
	}
	if s.directory != nil {
		s.directory.stop()
		s.directory = nil
	}
	if s.message != nil {
		s.message.stop()
		s.message = nil
	}
}
