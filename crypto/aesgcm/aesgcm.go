// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package aesgcm

import (
	"crypto/cipher"
	"crypto/aes"
)

type AESGCM struct {
}

func NewAESGCM() *AESGCM {
	return &AESGCM{}
}

func (ag *AESGCM) NewAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead, nil
}
