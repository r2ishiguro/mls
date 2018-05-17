// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package ecsig

import (
	"math/big"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/r2ishiguro/mls/crypto"
)

type ECSig struct {
	curve elliptic.Curve
	pub *ecdsa.PublicKey
	priv *ecdsa.PrivateKey
}

func New(curve elliptic.Curve) *ECSig {
	return &ECSig{
		curve: curve,
	}
}

func (ec *ECSig) Initialize(pub []byte, priv []byte) {
	x, y := elliptic.Unmarshal(ec.curve, pub)
	ec.pub = &ecdsa.PublicKey{ec.curve, x, y}
	ec.priv = &ecdsa.PrivateKey{*ec.pub, new(big.Int).SetBytes(priv)}
}

func (ec *ECSig) Sign(data []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, ec.priv, data)
	if err != nil {
		return nil, err
	}
	n := (ec.curve.Params().N.BitLen() + 7) / 8
	res := make([]byte, n*2)
	rs := r.Bytes()
	ss := s.Bytes()
	if len(rs) > n || len(ss) > n {
		return nil, crypto.ErrSignatureFormat
	}
	copy(res[n - len(rs):], rs)
	copy(res[2*n - len(ss):], ss)
	return res, nil
}

func (ec *ECSig) Verify(data []byte, sig []byte) error {
	n := (ec.curve.Params().N.BitLen() + 7) / 8
	if len(sig) != n * 2 {
		return crypto.ErrSignatureFormat
	}
	r := new(big.Int).SetBytes(sig[:n])
	s := new(big.Int).SetBytes(sig[n:])
	if !ecdsa.Verify(ec.pub, data, r, s) {
		return crypto.ErrSignatureVerification
	}
	return nil
}

func (ec *ECSig) PublicKey() []byte {
	return elliptic.Marshal(ec.curve, ec.pub.X, ec.pub.Y)
}

func (ec *ECSig) Generate() (pub []byte, priv []byte, err error) {
	ecpriv, err := ecdsa.GenerateKey(ec.curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return elliptic.Marshal(ec.curve, ecpriv.X, ecpriv.Y), ecpriv.D.Bytes(), nil
}

func (ec *ECSig) Size() int {
	return ((ec.curve.Params().N.BitLen() + 7) / 8) * 2
}

func (ec *ECSig) KeySize() (int, int) {
	return ((ec.curve.Params().BitSize + 7) / 8) * 2 + 1, (ec.curve.Params().N.BitLen() + 7) / 8
}
