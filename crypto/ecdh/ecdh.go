// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package ecdh

import (
	"math/big"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/r2ishiguro/mls/crypto"
)

type ECGroup struct {
	curve elliptic.Curve
}

type point struct {
	x, y *big.Int
}

func New(curve elliptic.Curve) *ECGroup {
	return &ECGroup{curve}
}

func (g *ECGroup) DH(b crypto.GroupElement, e crypto.GroupExponent) crypto.GroupElement {
	priv := e.([]byte)
	var r point
	if b != nil {
		p := b.(*point)
		r.x, r.y = g.curve.ScalarMult(p.x, p.y, priv)
	} else {
		r.x, r.y = g.curve.ScalarBaseMult(priv)
	}
	return &r
}

func (g *ECGroup) Injection(b crypto.GroupElement) crypto.GroupExponent {
	p := b.(*point)
	return p.x.Bytes()
}

func (g *ECGroup) Marshal(b crypto.GroupElement) []byte {
	p := b.(*point)
	return elliptic.Marshal(g.curve, p.x, p.y)
}

func (g *ECGroup) Unmarshal(os []byte) crypto.GroupElement {
	x, y := elliptic.Unmarshal(g.curve, os)
	return &point{x, y}
}

func (g *ECGroup) Encode(e crypto.GroupExponent) []byte {
	return e.([]byte)
}

func (g *ECGroup) Decode(os []byte) crypto.GroupExponent {
	return os
}

func (g *ECGroup) GenerateKey() (crypto.GroupElement, crypto.GroupExponent, error) {
	priv, x, y, err := elliptic.GenerateKey(g.curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &point{x, y}, priv, nil
}

func (g *ECGroup) Derive(r []byte) crypto.GroupExponent {
	// just make sure it's smaller than the group order
	e := new(big.Int).SetBytes(r)
	n := g.curve.Params().N
	if e.Cmp(n) >= 0 {
		e.Mod(e, n)
		r = e.Bytes()
	}
	return g.Decode(r)
}

func (g *ECGroup) Size() int {
	return (g.curve.Params().N.BitLen() + 7) / 8
}
