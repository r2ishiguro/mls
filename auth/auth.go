// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package auth

type AuthenticationService interface {
	Lookup(key []byte) (string, error)
	Register(key []byte, id string) error
	UId() string
}
