// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package mls

import (
	"crypto/sha256"
	"crypto/elliptic"
	"hash"
	"errors"

	"github.com/r2ishiguro/mls/crypto"
	"github.com/r2ishiguro/mls/crypto/ecdh"
	"github.com/r2ishiguro/mls/crypto/ecsig"
)

type CipherSuite byte
const (
	CipherUnknown CipherSuite = iota
	CipherX25519WithSHA256
	CipherP256R1WithSHA256
)

type SignatureScheme byte
const (
	SignatureUnknown SignatureScheme = iota
	SignatureEDDSA
	SignatureECDSA
)

type UserInitKey struct {
	Ciphers []CipherSuite
	InitKeys map[CipherSuite][]byte		// []DHPublicKey
	IdentityKey []byte			// SignaturePublicKey
	SignatureAlgorithm SignatureScheme
	Signature []byte
}

type GroupInitKey struct {
	Epoch uint32
	GroupSize uint32
	GroupId string
	Cipher CipherSuite
	AddKey []byte	// SUK PublicKey
	MerkleFrontier [][]byte
	RatchetFrontier [][]byte
}

type Signature struct {
	crypto.IdentitySignature
	algo SignatureScheme
}

var (
	ErrRatchetTree = errors.New("something wrong in ratchet tree")
	ErrMerkleTree = errors.New("something wrong in merkle tree")
	ErrUnsupported = errors.New("unsupported")
)

func NewDH(cipher CipherSuite) (crypto.GroupOperation, error) {
	switch cipher {
	case CipherX25519WithSHA256:
		// not supported yet
	case CipherP256R1WithSHA256:
		return ecdh.New(elliptic.P256()), nil
	}
	return nil, ErrUnsupported
}

func NewHash(cipher CipherSuite) (func() hash.Hash, error) {
	switch cipher {
	case CipherX25519WithSHA256:
		return sha256.New, nil
	case CipherP256R1WithSHA256:
		return sha256.New, nil
	}
	return nil, ErrUnsupported
}

func NewSignature(algo SignatureScheme) (*Signature, error) {
	var sig crypto.IdentitySignature
	switch algo {
	case SignatureEDDSA:
		// not supported yet
	case SignatureECDSA:
		sig = ecsig.New(elliptic.P256())
	}
	if sig == nil {
		return nil, ErrUnsupported
	}
	return &Signature{
		IdentitySignature: sig,
		algo: algo,
	}, nil
}

func (sig *Signature) Algorithm() SignatureScheme {
	return sig.algo
}
