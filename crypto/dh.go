// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package crypto

type GroupElement interface{}

type GroupExponent interface{}

type GroupOperation interface {
	DH(b GroupElement, e GroupExponent) GroupElement
	Injection(b GroupElement) GroupExponent
	Marshal(b GroupElement) []byte
	Unmarshal(os []byte) GroupElement
	Encode(e GroupExponent) []byte
	Decode(os []byte) GroupExponent
	GenerateKey() (GroupElement, GroupExponent, error)
	Derive(os []byte) GroupExponent		// only for the private part
	Size() int
}
