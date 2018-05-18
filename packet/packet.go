// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package packet

import (
	"io"
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/r2ishiguro/mls"
	"github.com/r2ishiguro/mls/crypto"
)

var (
	ErrUnknownMessageType = errors.New("unknown handshake message type")
)

//
// handshake protocols
//
type GroupAdd struct {
	UIK *mls.UserInitKey
}

type UserAdd struct {
	Path [][]byte	// DHPublicKey
}

type Update struct {
	Path [][]byte	// DHPublicKey
}

type Delete struct {
	Index uint32
	Path [][]byte	// DHPublicKey
}

type HandshakeType byte
const (
	HandshakeNone HandshakeType = 0
	HandshakeInit = 1
	HandshakeUserAdd = 2
	HandshakeGroupAdd = 3
	HandshakeUpdate = 4
	HandshakeDelete = 5
)

type HandshakeMessage struct {
	Type HandshakeType
	Data interface{}
	PriorEpoch uint32
	GIK *mls.GroupInitKey
	SignerIndex uint32
	MerkleProof [][]byte
	IdentityKey []byte	// SignaturePublicKey
	SignatureAlgorithm mls.SignatureScheme
	Signature []byte
}

/*
enum {
       none(0),
       init(1),
       user_add(2),
       group_add(3),
       update(4),
       delete(5),
       (255)
} HandshakeType;

struct {
       HandshakeType msg_type;
       uint24 inner_length;
       select (Handshake.msg_type) {
           case none:      struct{};
           case init:      Init;
           case user_add:  UserAdd;
           case group_add: GroupAdd;
           case update:    Update;
           case delete:    Delete;
       };

       uint32 prior_epoch;
       GroupInitKey init_key;

       uint32 signer_index;
       MerkleNode identity_proof<1..2^16-1>;
       SignaturePublicKey identity_key;

       SignatureScheme algorithm;
       opaque signature<1..2^16-1>;
} Handshake;
*/

func MarshalHandshake(msg *HandshakeMessage, sig crypto.IdentitySignature) ([]byte, error) {
	var buf bytes.Buffer
	
	switch msg.Type {
	case HandshakeGroupAdd:
		if err := WriteUIK(&buf, msg.Data.(*GroupAdd).UIK); err != nil {
			return nil, err
		}
	case HandshakeUserAdd:
		if err := writePath(&buf, msg.Data.(*UserAdd).Path, 16); err != nil {
			return nil, err
		}
	case HandshakeUpdate:
		if err := writePath(&buf, msg.Data.(*Update).Path, 16); err != nil {
			return nil, err
		}
	case HandshakeDelete:
		del := msg.Data.(*Delete)
		if err := binary.Write(&buf, binary.BigEndian, del.Index); err != nil {
			return nil, err
		}
		if err := writePath(&buf, del.Path, 16); err != nil {
			return nil, err
		}
	case HandshakeNone:
		// no data
	case HandshakeInit:
		// no data
	default:
		return nil, ErrUnknownMessageType
	}

	if err := binary.Write(&buf, binary.BigEndian, msg.PriorEpoch); err != nil {	// priorEpoch from the current state
		return nil, err
	}
	if err := WriteGIK(&buf, msg.GIK); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, msg.SignerIndex); err != nil {
		return nil, err
	}
	if err := writePath(&buf, msg.MerkleProof, 8); err != nil {
		return nil, err
	}
	if err := WriteChunk(&buf, msg.IdentityKey, 16); err != nil {
		return nil, err
	}
	// signatureAlgorithm
	if err := binary.Write(&buf, binary.BigEndian, uint16(msg.SignatureAlgorithm)); err != nil {	// @@ no description in the current draft... assume it's uint16
		return nil, err
	}

	// ... now we can sign the message...
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(buf.Len() + sig.Size() + 2/* sizeof(uint16) */))	// put the inner length
	header[0] = byte(msg.Type)
	tbs := append(header[:], buf.Bytes()...)
	signature, err := sig.Sign(tbs)
	if err != nil {
		return nil, err
	}

	// put all together
	if err := WriteChunk(&buf, signature, 16); err != nil {
		return nil, err
	}
	return append(header[:], buf.Bytes()...), nil
}

func UnmarshalHandshake(r io.Reader) (*HandshakeMessage, []byte, error) {
	var msg HandshakeMessage

	// read the header
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, nil, err
	}
	var t [4]byte
	copy(t[:], header[:])
	t[0] = 0
	innerlen := binary.BigEndian.Uint32(t[:])
	if innerlen < 3 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	data := make([]byte, len(header) + int(innerlen))
	if _, err := io.ReadFull(r, data[len(header):]); err != nil {
		return nil, nil, err
	}
	copy(data[:len(header)], header[:])
	r = bytes.NewReader(data[len(header):])	// switch to the memory reader

	msg.Type = HandshakeType(header[0])
	switch msg.Type {
	case HandshakeNone:
	case HandshakeInit:
		// no data
	case HandshakeUserAdd:
		path, err := readPath(r, 16)
		if err != nil {
			return nil, nil, err
		}
		msg.Data = &UserAdd{path}
	case HandshakeGroupAdd:
		uik, err := ReadUIK(r)
		if err != nil {
			return nil, nil, err
		}
		msg.Data = &GroupAdd{uik}
	case HandshakeUpdate:
		path, err := readPath(r, 16)
		if err != nil {
			return nil, nil, err
		}
		msg.Data = &Update{path}
	case HandshakeDelete:
		var idx uint32
		if err := binary.Read(r, binary.BigEndian, &idx); err != nil {
			return nil, nil, err
		}
		path, err := readPath(r, 16)
		if err != nil {
			return nil, nil, err
		}
		msg.Data = &Delete{idx, path}
	default:
		return nil, nil, ErrUnknownMessageType
	}

	if err := binary.Read(r, binary.BigEndian, &msg.PriorEpoch); err != nil {
		return nil, nil, err
	}
	var err error
	msg.GIK, err = ReadGIK(r)
	if err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &msg.SignerIndex); err != nil {
		return nil, nil, err
	}
	msg.MerkleProof, err = readPath(r, 8)
	if err != nil {
		return nil, nil, err
	}
	msg.IdentityKey, err = ReadChunk(r, 16)
	if err != nil {
		return nil, nil, err
	}
	var algo uint16		// @@ no description in the current draft... assume it's uint16
	if err := binary.Read(r, binary.BigEndian, &algo); err != nil {
		return nil, nil, err
	}
	msg.SignatureAlgorithm = mls.SignatureScheme(algo)
	msg.Signature, err = ReadChunk(r, 16)
	if err != nil {
		return nil, nil, err
	}

	// check the message signature -- merkle tree proof and authenticity of IdentityKey will be checked by the caller
	sig, err := mls.NewSignature(msg.SignatureAlgorithm)
	if err != nil {
		return nil, nil, err
	}
	sig.Initialize(msg.IdentityKey, nil)
	tbs := data[:len(msg.Signature)+2]
	if err := sig.Verify(tbs, msg.Signature); err != nil {
		return nil, nil, err
	}
	return &msg, data, nil
}

/*
   struct {
       CipherSuite cipher_suites<0..255>;
       DHPublicKey init_keys<1..2^16-1>;
       SignaturePublicKey identity_key;
       SignatureScheme algorithm;
       opaque signature<0..2^16-1>;
   } UserInitKey;
*/

func UserInitKeyTBS(uik *mls.UserInitKey) ([]byte, error) {
	// 7.1. "The input to the signature computation comprises all of the fields except for the signature field."
	var buf bytes.Buffer
	if _, err := buf.Write([]byte{byte(len(uik.Ciphers))}); err != nil {
		return nil, err
	}
	for _, cipher := range uik.Ciphers {
		if err := binary.Write(&buf, binary.BigEndian, uint16(cipher)); err != nil {
			return nil, err
		}
	}
	for _, cipher := range uik.Ciphers {
		ik, ok := uik.InitKeys[cipher]
		if !ok {
			return nil, mls.ErrUnsupported
		}
		if err := WriteChunk(&buf, ik, 16); err != nil {
			return nil, err
		}
	}
	if err := WriteChunk(&buf, uik.IdentityKey, 16); err != nil {
		return nil, err
	}
	// there's no definition of SignatureScheme in the current spec. Assume it's uint16
	if err := binary.Write(&buf, binary.BigEndian, uint16(uik.SignatureAlgorithm)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func ReadUIK(r io.Reader) (*mls.UserInitKey, error) {
	var uik mls.UserInitKey
	nciphers, err := ReadByte(r)
	if err != nil {
		return nil, err
	}
	uik.Ciphers = make([]mls.CipherSuite, nciphers)
	for i := 0; i < int(nciphers); i++ {
		var cipher uint16
		if err := binary.Read(r, binary.BigEndian, &cipher); err != nil {
			return nil, err
		}
		uik.Ciphers[i] = mls.CipherSuite(cipher)
	}
	uik.InitKeys = make(map[mls.CipherSuite][]byte)
	for _, cipher := range uik.Ciphers {
		ik, err := ReadChunk(r, 16)
		if err != nil {
			return nil, err
		}
		uik.InitKeys[cipher] = ik
	}
	uik.IdentityKey, err = ReadChunk(r, 16)
	if err != nil {
		return nil, err
	}
	var algo uint16		// @@ no description in the current draft... assume it's uint16
	if err := binary.Read(r, binary.BigEndian, &algo); err != nil {
		return nil, err
	}
	uik.SignatureAlgorithm = mls.SignatureScheme(algo)
	uik.Signature, err = ReadChunk(r, 16)
	if err != nil {
		return nil, err
	}
	return &uik, nil
}

func WriteUIK(w io.Writer, uik *mls.UserInitKey) error {
	tbs, err := UserInitKeyTBS(uik)
	if err != nil {
		return err
	}
	if _, err := w.Write(tbs); err != nil {
		return err
	}
	if err := WriteChunk(w, uik.Signature, 16); err != nil {
		return err
	}
	return nil
}

/*
 struct {
       uint32 epoch;
       uint32 group_size;
       opaque group_id<0..2^16-1>;
       CipherSuite cipher_suite;
       DHPublicKey add_key;
       MerkleNode identity_frontier<0..2^16-1>;
       DHPublicKey ratchet_frontier<0..2^16-1>;
 } GroupInitKey;
*/

func ReadGIK(r io.Reader) (*mls.GroupInitKey, error) {
	var gik mls.GroupInitKey
	if err := binary.Read(r, binary.BigEndian, &gik.Epoch); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &gik.GroupSize); err != nil {
		return nil, err
	}
	gid, err := ReadChunk(r, 16)
	if err != nil {
		return nil, err
	}
	gik.GroupId = string(gid)
	var cipher uint16
	if err := binary.Read(r, binary.BigEndian, &cipher); err != nil {
		return nil, err
	}
	gik.Cipher = mls.CipherSuite(cipher)
	gik.AddKey, err = ReadChunk(r, 16)
	if err != nil {
		return nil, err
	}
	gik.MerkleFrontier, err = readPath(r, 8)
	if err != nil {
		return nil, err
	}
	gik.RatchetFrontier, err = readPath(r, 16)
	if err != nil {
		return nil, err
	}
	return &gik, nil
}

func WriteGIK(w io.Writer, gik *mls.GroupInitKey) error {
	if err := binary.Write(w, binary.BigEndian, gik.Epoch); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, gik.GroupSize); err != nil {
		return err
	}
	if err := WriteChunk(w, []byte(gik.GroupId), 16); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint16(gik.Cipher)); err != nil {
		return err
	}
	if err := WriteChunk(w, gik.AddKey, 16); err != nil {
		return err
	}
	if err := writePath(w, gik.MerkleFrontier, 8); err != nil {
		return err
	}
	if err := writePath(w, gik.RatchetFrontier, 16); err != nil {
		return err
	}
	return nil
}

/*
struct {
       uint16 length = Length;
       opaque label<7..255> = "mls10 " + Label;
       opaque group_id<0..2^16-1> = ID;
       uint32 epoch = Epoch;
       opaque message<1..2^16-1> = Msg
} HkdfLabel;
*/

func HkdfLabel(label string, id string, epoch uint32, msg []byte, length int) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint16(length)); err != nil {
		return nil, err
	}
	label = "mls10 " + label
	if err := buf.WriteByte(byte(len(label))); err != nil {
		return nil, err
	}
	if _, err := buf.Write([]byte(label)); err != nil {
		return nil, err
	}
	if err := WriteChunk(&buf, []byte(id), 16); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint32(epoch)); err != nil {
		return nil, err
	}
	if err := WriteChunk(&buf, msg, 16); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func readPath(r io.Reader, sz int) (path [][]byte, err error) {
	var pathlen uint16
	if err := binary.Read(r, binary.BigEndian, &pathlen); err != nil {
		return nil, err
	}
	path = make([][]byte, pathlen)
	for i := 0; i < int(pathlen); i++ {
		path[i], err = ReadChunk(r, sz)
		if err != nil {
			return nil, err
		}
	}
	return path, nil
}

func writePath(w io.Writer, path [][]byte, sz int) error {
	if err := binary.Write(w, binary.BigEndian, uint16(len(path))); err != nil {
		return err
	}
	for _, p := range path {
		if err := WriteChunk(w, p, sz); err != nil {
			return err
		}
	}
	return nil
}

func ReadChunk(r io.Reader, sz int) (chunk []byte, err error) {
	var l int
	if sz == 8 {
		var l8 uint8
		l8, err = ReadByte(r)
		l = int(l8)
	} else if sz == 16 {
		var l16 uint16
		err = binary.Read(r, binary.BigEndian, &l16)
		l = int(l16)
	} else {
		var l32 uint32
		err = binary.Read(r, binary.BigEndian, &l32)
		l = int(l32)
	}
	if err != nil {
		return nil, err
	}
	chunk = make([]byte, l)
	if _, err := io.ReadFull(r, chunk); err != nil {
		return nil, err
	}
	return chunk, nil
}

func WriteChunk(w io.Writer, c []byte, sz int) (err error) {
	l := len(c)
	if sz == 8 {
		err = binary.Write(w, binary.BigEndian, uint8(l))
	} else if sz == 16 {
		err = binary.Write(w, binary.BigEndian, uint16(l))
	} else {
		err = binary.Write(w, binary.BigEndian, uint32(l))
	}
	if err == nil {
		_, err = w.Write(c)
	}
	return err
}

func ReadByte(r io.Reader) (byte, error) {
	var c [1]byte
	if _, err := io.ReadFull(r, c[:]); err != nil {
		return 0, err
	}
	return c[0], nil
}

func WriteByte(w io.Writer, c byte) error {
	_, err := w.Write([]byte{c})
	return err
}
