// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package crypto

import (
	"crypto/cipher"
	"errors"
)

var (
	ErrKeyGenerationMismatch = errors.New("key generation mismatch")
)

type DataEncryption interface {
	NewAEAD(key []byte) (cipher.AEAD, error)
}
