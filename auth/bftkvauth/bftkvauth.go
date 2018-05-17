// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package bftkvauth

import (
	"github.com/yahoo/bftkv/api"
)

type BftkvAuth struct {
	bftkv *api.API
}

func Open(path string) (*BftkvAuth, error) {
	client, err := api.OpenClient(path)
	if err != nil {
		return nil, err
	}
	return &BftkvAuth{client}, nil
}

func (auth *BftkvAuth) Lookup(key []byte) (string, error) {
	id, err := auth.bftkv.Read(key, "")
	if err != nil {
		return "", err
	}
	return string(id), nil
}

func (auth *BftkvAuth) Register(key []byte, id string) error {
	return auth.bftkv.Write(key, []byte(id), "")
}

func (auth *BftkvAuth) UId() string {
	return auth.bftkv.UId()
}
