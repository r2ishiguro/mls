// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package protocol

import (
	"io"
	"crypto/rand"
	"encoding/binary"

	"github.com/r2ishiguro/mls"
	"github.com/r2ishiguro/mls/ds"
	"github.com/r2ishiguro/mls/crypto"
	"github.com/r2ishiguro/mls/auth"
)

const (
	FrameSize = 16*1024	// same as TLS
)

type Message struct {
	keymap map[string]string
	auth auth.AuthenticationService
	svc *ds.MessageService
	channel *GroupChannel
}

func (c *GroupChannel) NewMessage(msgAddr string) (*Message, error) {
	svc, err := ds.NewMessageService(msgAddr, c.gid)
	if err != nil {
		return nil, err
	}
	msg := &Message{
		keymap: make(map[string]string),
		auth: c.protocol.auth,
		svc: svc,
		channel: c,
	}
	c.message = msg
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
	sig := m.channel.protocol.sig

	aead, err := m.channel.protocol.aead.NewAEAD(m.channel.state.MessageKey())
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
		binary.BigEndian.PutUint32(ebuf[:], m.channel.state.Epoch())
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

	aead, err := m.channel.protocol.aead.NewAEAD(m.channel.state.MessageKey())
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
	if epoch != m.channel.state.Epoch() {
		return nil, "", crypto.ErrKeyGenerationMismatch
	}
	tag := ciphertext[tagpos:noncepos]	// including epoch

	// verify the signature
	uid, ok := m.keymap[string(key)]
	if !ok {
		uid, err = m.auth.Lookup(key)
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
