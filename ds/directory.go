// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package ds

import (
	"net"
	"io"
	"time"
	"bytes"
	"strings"
	"encoding/binary"
	"errors"
	"log"

	"github.com/r2ishiguro/mls"
	"github.com/r2ishiguro/mls/ds/keystore"
	"github.com/r2ishiguro/mls/packet"
)

var (
	ErrRegister = errors.New("registration failed")
)

// Directory service messages are not defined explicitly at the moment
/*
enum {
	register(1),
	lookup(2),
	delete(3),
	list(4),
	(255)
} DirectoryServiceType

enum {
	user(1),
	group(2),
	(255)
} DataType

struct {
	DirectoryServiceType msg_type;
	opqaue id<1..2^16-1>	// same length as the group id
	DataType dataType;
	select (DirectoryService.msg_type) {
		case register:	opaque<1..2^16-1>;	// opaque from the directory service
		case lookup:	struct{};
		case delete:	struct{};
	};
} DiretoryServiceRequest
*/


type directoryMessageType byte
const (
	directoryMessageTypeNone directoryMessageType = 0
	directoryMessageTypeRegister = 1
	directoryMessageTypeLookup = 2
	directoryMessageTypeDelete = 3
	directoryMessageTypeList = 4
)

type directoryDataType byte
const (
	directoryDataTypeNone directoryDataType = 0
	directoryDataTypeUser = 1
	directoryDataTypeGroup = 2
)

type directoryRequest struct {
	msgType directoryMessageType
	id string
	dataType directoryDataType
	data []byte
}

type directoryResponse struct {
	dataType directoryDataType
	data []byte
}

const directoryTimeout = 10	// in sec

//
// client side
//
type DirectoryService struct {
	addr string
}

func NewDirectoryService(addr string) *DirectoryService {
	return &DirectoryService{
		addr: addr,
	}
}

func (d *DirectoryService) RegisterUIK(uid string, uik *mls.UserInitKey) error {
	var buf bytes.Buffer
	if err := packet.WriteUIK(&buf, uik); err != nil {
		return err
	}
	return d.register(uid, buf.Bytes(), directoryDataTypeUser)
}

func (d *DirectoryService) RegisterGIK(gid string, gik *mls.GroupInitKey) error {
	var buf bytes.Buffer
	if err := packet.WriteGIK(&buf, gik); err != nil {
		return err
	}
	return d.register(gid, buf.Bytes(), directoryDataTypeGroup)
}

func (d *DirectoryService) register(id string, data []byte, dataType directoryDataType) error {
	res, err := d.send(&directoryRequest{
		msgType: directoryMessageTypeRegister,
		id: id,
		dataType: dataType,
		data: data,
	})
	if err != nil {
		return err
	}
	if res.dataType != dataType {
		return ErrRegister
	}
	return nil
}

func (d *DirectoryService) LookupUser(uid string) (*mls.UserInitKey, error) {
	res, err := d.lookup(uid, directoryDataTypeUser)
	if err != nil {
		return nil, err
	}
	return packet.ReadUIK(bytes.NewReader(res))
}

func (d *DirectoryService) LookupGroup(gid string) (*mls.GroupInitKey, error) {
	res, err := d.lookup(gid, directoryDataTypeGroup)
	if err != nil {
		return nil, err
	}
	return packet.ReadGIK(bytes.NewReader(res))
}

func (d *DirectoryService) lookup(id string, dataType directoryDataType) ([]byte, error) {
	res, err := d.send(&directoryRequest{
		msgType: directoryMessageTypeLookup,
		id: id,
		dataType: dataType,
	})
	if err != nil {
		return nil, err
	}
	return res.data, nil
}

func (d *DirectoryService) DeleteUser(uid string) error {
	return d.delete(uid, directoryDataTypeUser)
}

func (d *DirectoryService) DeleteGroup(gid string) error {
	return d.delete(gid, directoryDataTypeGroup)
}

func (d *DirectoryService) delete(id string, dataType directoryDataType) error {
	_, err := d.send(&directoryRequest{
		msgType: directoryMessageTypeDelete,
		id: id,
		dataType: dataType,
	})
	if err != nil {
		return err
	}
	return nil
}

func (d *DirectoryService) ListUsers() []string {
	return d.list(directoryDataTypeUser)
}

func (d *DirectoryService) ListGroups() []string {
	return d.list(directoryDataTypeGroup)
}

func (d *DirectoryService) list(dataType directoryDataType) (list []string) {
	res, err := d.send(&directoryRequest{
		msgType: directoryMessageTypeList,
		dataType: dataType,
	})
	if err != nil {
		return
	}
	r := bytes.NewReader(res.data)
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return
	}
	for ; n > 0; n-- {
		s, err := packet.ReadChunk(r, 16)
		if err != nil {
			break
		}
		list = append(list, string(s))
	}
	return list
}

func (d *DirectoryService) send(req *directoryRequest) (*directoryResponse, error) {
	conn, err := net.Dial("tcp", d.addr)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(directoryTimeout * time.Second))	// both read/write, which means the total timeout is 2*directoryTimeout in no response?
	defer conn.Close()
	
	if err := marshalDirectoryRequest(conn, req); err != nil {
		return nil, err
	}
	return unmarshalDirectoryResponse(conn)
}

//
// server side
//
type directoryServer struct {
	listener net.Listener
	ks keystore.KeyStore
}

func startDirectoryServer(addr string, ks keystore.KeyStore) (*directoryServer, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &directoryServer{
		listener: l,
		ks: ks,
	}

	go func(l net.Listener) {
		for {
			conn, err := l.Accept()
			if err != nil {
				log.Printf("directory: Accept() failed: %s", err)
				break
			}
			go func(conn net.Conn) {
				if err := s.handler(conn); err != nil {
					log.Printf("directory: %s", err)
				}
				conn.Close()
			}(conn)
		}
	}(l)
	return s, nil
}

func (s *directoryServer) stop() {
	s.listener.Close()
}

func (s *directoryServer) handler(conn net.Conn) error {
	req, err := unmarshalDirectoryRequest(conn)
	if err != nil {
		return err
	}

	var prefix string
	if req.dataType == directoryDataTypeUser {
		prefix = "#U_"
	} else {
		prefix = "#G_"
	}

	var res []byte
	switch int(req.msgType) {
	case directoryMessageTypeRegister:	// register
		if err = s.ks.Register(prefix + req.id, req.data); err != nil {
			return err
		}
		// can be overwritten by anyone..
		// to avoid the DoS type attack checking the signer with the authentication server would be effective but leave it to clients for now
		// note that even if the directory service checks the authenticity of the signer clients must verify it themselves, as DS has no credential
	case directoryMessageTypeLookup:	// lookup
		res, err = s.ks.Lookup(prefix + req.id)
		if err != nil {
			return err
		}
	case directoryMessageTypeDelete:	// delete
		if err = s.ks.Delete(prefix + req.id); err != nil {
			return err
		}
	case directoryMessageTypeList:
		var w bytes.Buffer
		list, err := s.ks.List()
		if err != nil {
			return err
		}
		if err := binary.Write(&w, binary.BigEndian, uint32(len(list))); err != nil {
			return err
		}
		for _, id := range list {
			if strings.HasPrefix(id, prefix) {
				if err := packet.WriteChunk(&w, []byte(id[len(prefix):]), 16); err != nil {
					return err
				}
			}
		}
		res = w.Bytes()
	}
	conn.SetWriteDeadline(time.Now().Add(directoryTimeout * time.Second))
	return marshalDirectoryResponse(conn, &directoryResponse{req.dataType, res})
}

func marshalDirectoryRequest(w io.Writer, req *directoryRequest) error {
	if err := packet.WriteByte(w, byte(req.msgType)); err != nil {
		return err
	}
	if err := packet.WriteChunk(w, []byte(req.id), 16); err != nil {
		return err
	}
	if err := packet.WriteByte(w, byte(req.dataType)); err != nil {
		return err
	}
	if err := packet.WriteChunk(w, req.data, 16); err != nil {
		return err
	}
	return nil
}

func unmarshalDirectoryRequest(r io.Reader) (*directoryRequest, error) {
	var req directoryRequest
	t, err := packet.ReadByte(r)
	if err != nil {
		return nil, err
	}
	req.msgType = directoryMessageType(t)
	id, err := packet.ReadChunk(r, 16)
	if err != nil {
		return nil, err
	}
	req.id = string(id)
	t, err = packet.ReadByte(r)
	if err != nil {
		return nil, err
	}
	req.dataType = directoryDataType(t)
	req.data, err = packet.ReadChunk(r, 16)
	if err != nil {
		return nil, err
	}
	return &req, nil
}

func marshalDirectoryResponse(w io.Writer, res *directoryResponse) error {
	if err := packet.WriteByte(w, byte(res.dataType)); err != nil {
		return err
	}
	if err := packet.WriteChunk(w, res.data, 16); err != nil {
		return err
	}
	return nil
}

func unmarshalDirectoryResponse(r io.Reader) (*directoryResponse, error) {
	t, err := packet.ReadByte(r)
	if err != nil {
		return nil, err
	}
	d, err := packet.ReadChunk(r, 16)
	if err != nil {
		return nil, err
	}
	return &directoryResponse{directoryDataType(t), d}, nil
}
