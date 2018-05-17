// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package keystore

type KeyStore interface {
	Register(id string, key []byte) error
	Lookup(id string) ([]byte, error)
	Delete(id string) error
	List() ([]string, error)
}
