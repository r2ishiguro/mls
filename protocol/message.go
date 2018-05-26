// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package protocol

import (
	"io"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/r2ishiguro/mls"
	"github.com/r2ishiguro/mls/ds"
)

var (
	ErrKeyGenerationMismatch = errors.New("key generation mismatch")
)

const (
	FrameSize = 16*1024	// same as TLS
)

type Message struct {
	keymap map[string]string
	svc *ds.MessageService
	p *Protocol
	g *GroupState
}

func NewMessage(msgAddr string, gid string, p *Protocol, g *GroupState) (*Message, error) {
	svc, err := ds.NewMessageService(msgAddr, gid)
	if err != nil {
		return nil, err
	}
	msg := &Message{
		keymap: make(map[string]string),
		svc: svc,
		p: p,
		g: g,
	}
	return msg, nil
}

func (m *Message) Close() {
	if m.svc != nil {
		m.svc.Close()
		m.svc = nil
	}
}

/*

ciphertext format:

     |  ciphertext | tag | epoch | nonce | id-key | signature | algo |
     |        AEAD       |
     |             |     TBS     |

put algo at the end of ciphertext so the signature scheme can be constructed with it, which the size of signature and key depends on

*/

func (m *Message) Send(msg []byte) error {
	sig := m.p.sig

	aead, err := m.p.aead.NewAEAD(m.g.MessageKey())
	if err != nil {
		return err
	}

	for len(msg) > 0 {
		nonce := make([]byte, aead.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return err
		}
		n := len(msg)
		if n > FrameSize {
			n = FrameSize
		}
		ciphertext := aead.Seal(nil, nonce, msg[:n], nil)
		msg = msg[n:]
		tagpos := len(ciphertext) - aead.Overhead()

		// append epoch
		var ebuf [4]byte
		binary.BigEndian.PutUint32(ebuf[:], m.g.Epoch())
		ciphertext = append(ciphertext, ebuf[:]...)

		// calculate the signature over the tag + epoch
		signature, err := sig.Sign(ciphertext[tagpos:])
		if err != nil {
			return err
		}

		// append nonce and (algo, pubkey, signature)
		ciphertext = append(ciphertext, append(nonce, append(sig.PublicKey(), append(signature, byte(sig.Algorithm()))...)...)...)

		if err := m.svc.Send(ciphertext); err != nil {
			return err
		}
	}
	return nil
}

func (m *Message) Receive() ([]byte, string, error) {
	ciphertext, err := m.svc.Receive()
	if err != nil {
		return nil, "", err
	}

	aead, err := m.p.aead.NewAEAD(m.g.MessageKey())
	if err != nil {
		return nil, "", err
	}

	// first construct a signature scheme with the algo
	algopos := len(ciphertext) - 1
	sig, err := mls.NewSignature(mls.SignatureScheme(ciphertext[algopos]))
	if err != nil {
		return nil, "", err
	}
	keysize, _ := sig.KeySize()

	// calculate the position of each component
	sigpos := algopos - sig.Size()
	keypos := sigpos - keysize
	noncepos := keypos - aead.NonceSize()
	epochpos := noncepos - 4	// sizeof uint32
	tagpos := epochpos - aead.Overhead()
	signature := ciphertext[sigpos:algopos]
	key := ciphertext[keypos:sigpos]
	nonce := ciphertext[noncepos:keypos]
	epoch := binary.BigEndian.Uint32(ciphertext[epochpos:noncepos])
	if epoch != m.g.Epoch() {
		fmt.Printf("[%s] epoch mismatch: got = %d, have = %d\n", m.p.self, epoch, m.g.Epoch())
		return nil, "", ErrKeyGenerationMismatch
	}
	tag := ciphertext[tagpos:noncepos]	// including epoch

	// verify the signature
	uid, ok := m.keymap[string(key)]
	if !ok {
		uid, err = m.p.auth.Lookup(key)
		if err != nil {
			return nil, "", err
		}
		m.keymap[string(key)] = uid
	}
	sig.Initialize(key, nil)
	if err := sig.Verify(tag, signature); err != nil {
		return nil, "", err
	}

	// finally, we can decrypt...
	plain, err := aead.Open(nil, nonce, ciphertext[:epochpos], nil)
	return plain, uid, err
}
