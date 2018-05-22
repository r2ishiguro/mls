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
	"github.com/r2ishiguro/mls/crypto"
)

var (
	ErrUnauthorizedSender = errors.New("unauthorized sender")
)

type Message struct {
	svc *ds.MessageService
	channel *GroupChannel
}

func (c *GroupChannel) NewMessage(msgAddr string) (*Message, error) {
	svc, err := ds.NewMessageService(msgAddr, c.gid)
	if err != nil {
		return nil, err
	}
	msg := &Message{
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

     |  ciphertext | tag | epoch | nonce | signer idx | signature | algo |
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

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := aead.Seal(nil, nonce, msg, nil)
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
	var signerIndex [4]byte
	idx, _ := m.channel.state.Proof()	// we don't need the Merkle proof right??
	fmt.Printf("message: sender = %d\n", idx)
	binary.BigEndian.PutUint32(signerIndex[:], uint32(idx))
	ciphertext = append(ciphertext, append(nonce, append(signerIndex[:], append(signature, byte(sig.Algorithm()))...)...)...)

	return m.svc.Send(ciphertext)
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

	// calculate the position of each component
	sigpos := algopos - sig.Size()
	idxpos := sigpos - 4
	noncepos := idxpos - aead.NonceSize()
	epochpos := noncepos - 4	// sizeof uint32
	tagpos := epochpos - aead.Overhead()
	signature := ciphertext[sigpos:algopos]
	idx := ciphertext[idxpos:sigpos]
	nonce := ciphertext[noncepos:idxpos]
	epoch := binary.BigEndian.Uint32(ciphertext[epochpos:noncepos])
	if epoch != m.channel.state.Epoch() {
		fmt.Printf("message: key generation mismatch: %d vs %d\n", epoch, m.channel.state.Epoch())
		return nil, "", crypto.ErrKeyGenerationMismatch
	}
	tag := ciphertext[tagpos:noncepos]	// including epoch

	// verify the signature
	signerIdx := binary.BigEndian.Uint32(idx)
	peer, ok := m.channel.peers[int(signerIdx)]
	if !ok {
		return nil, "", ErrUnauthorizedSender
	}
	sig.Initialize(peer.identityKey, nil)
	if err := sig.Verify(tag, signature); err != nil {
		fmt.Printf("message: verify failed: %s (%d)\n", peer.uid, signerIdx)
		return nil, "", err
	}

	// finally, we can decrypt...
	plain, err := aead.Open(nil, nonce, ciphertext[:epochpos], nil)
	if err != nil {
		return nil, "", err
	}
	return plain, peer.uid, nil
}
