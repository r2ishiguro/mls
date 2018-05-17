// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package simplekv

import (
	"sync"
)

type SimpleKeyStore struct {
	store map[string][]byte
	mutex sync.Mutex
}

func New() *SimpleKeyStore {
	return &SimpleKeyStore{
		store: make(map[string][]byte),
	}
}

func (s *SimpleKeyStore) Register(id string, key []byte) error {
	s.mutex.Lock()
	s.store[id] = key
	s.mutex.Unlock()
	return nil
}

func (s *SimpleKeyStore) Lookup(id string) ([]byte, error) {
	s.mutex.Lock()
	key, ok := s.store[id]
	s.mutex.Unlock()
	if !ok {
		key = nil
	}
	return key, nil
}

func (s *SimpleKeyStore) Delete(id string) error {
	s.mutex.Lock()
	delete(s.store, id)
	s.mutex.Unlock()
	return nil
}

func (s *SimpleKeyStore) List() ([]string, error) {
	var list []string
	for id, _ := range s.store {
		list = append(list, id)
	}
	return list, nil
}
