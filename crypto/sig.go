// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package crypto

import "errors"

var (
	ErrSignatureFormat = errors.New("sig: malformed signature format")
	ErrSignatureVerification = errors.New("sig: verification failed")
)

type IdentitySignature interface {
	Sign(data []byte) (sig []byte, err error)
	Verify(data []byte, sig []byte) error
	PublicKey() []byte
	Generate() (pub, priv []byte, err error)
	Initialize(pub, priv []byte)
	Size() (sigSize int)
	KeySize() (pubSize int, privSize int)
}
