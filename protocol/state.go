// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package protocol

import (
	"sync"
	"io"
	"hash"

	"golang.org/x/crypto/hkdf"

	"github.com/r2ishiguro/mls"
	"github.com/r2ishiguro/mls/art"
	"github.com/r2ishiguro/mls/merkle"
	"github.com/r2ishiguro/mls/crypto"
	"github.com/r2ishiguro/mls/packet"
)

type GroupState struct {
	gid string
	cipherSuite mls.CipherSuite
	ratchetTree *art.RatchetTree
	merkleTree *merkle.MerkleTree
	epoch uint32
	suk crypto.GroupExponent	// add key (private)
	sukPub crypto.GroupElement	// add key (public)
	messageSecret []byte		// message master secret
	initSecret []byte
	self int			// the leaf index
	privKey []byte			// the private key corresponding to the leaf index
	mutex sync.Mutex
	sig *mls.Signature
	dh crypto.GroupOperation
	hash func() hash.Hash
}

func NewGroupState(gid string, cipher mls.CipherSuite, sig *mls.Signature) (*GroupState, error) {
	dh, err := mls.NewDH(cipher)
	if err != nil {
		return nil, err
	}
	hash, err := mls.NewHash(cipher)
	if err != nil {
		return nil, err
	}
	_, suk, err := dh.GenerateKey()
	if err != nil {
		return nil, err
	}
	g := &GroupState{
		gid: gid,
		cipherSuite: cipher,
		dh: dh,
		hash: hash,
		initSecret: make([]byte, hash().Size()),
		messageSecret: make([]byte, hash().Size()),	// the message encryption key size = hash size,
		suk: suk,
		sukPub: nil,
		sig: sig,
	}

	g.ratchetTree = art.New(g.dh, nil, 0)
	g.merkleTree = merkle.New(g.hash, nil, 0)
	g.epoch = 0
	return g, nil
}

func NewGroupStateWithGIK(gik *mls.GroupInitKey, sig *mls.Signature) (*GroupState, error) {
	g, err := NewGroupState(gik.GroupId, gik.Cipher, sig)
	if err != nil {
		return nil, err
	}
	g.sukPub = g.dh.Unmarshal(gik.AddKey)	// keep this SUK until the instance's gone

	g.ratchetTree = art.New(g.dh, gik.RatchetFrontier, int(gik.GroupSize))
	g.merkleTree = merkle.New(g.hash, gik.MerkleFrontier, int(gik.GroupSize))
	g.epoch = gik.Epoch
	return g, nil
}

func (g *GroupState) AddSelf(privKey []byte, identityKey []byte) (int, error) {
	// add the self node
	var e crypto.GroupExponent
	if g.sukPub != nil {
		e = g.dh.Injection(g.dh.DH(g.sukPub, g.dh.Decode(privKey)))
	} else {
		e = g.dh.Decode(privKey)
	}
	idx := g.ratchetTree.Add(e)
	if idx < 0 {
		return -1, mls.ErrRatchetTree
	}
	if g.merkleTree.Add(identityKey) != idx {
		return -1, mls.ErrRatchetTree
	}
	g.self = idx
	g.privKey = privKey
	return idx, nil
}

func (g *GroupState) AddUser(uik *mls.UserInitKey) (int, error) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	// update the ratchet tree
	ek, ok := uik.InitKeys[g.cipherSuite]	// the public key of the adding user
	if !ok {
		return -1, ErrKeyNotFound
	}
	idx := g.ratchetTree.Add(g.dh.Injection(g.dh.DH(g.dh.Unmarshal(ek), g.suk)))
	if idx < 0 {
		return -1, mls.ErrRatchetTree
	}
	// update the merkle tree
	if g.merkleTree.Add(uik.IdentityKey) != idx {
		return -1, mls.ErrMerkleTree
	}
	return idx, nil
}

func (g *GroupState) AddPath(path [][]byte, identityKey []byte) (int, error) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	idx := g.ratchetTree.AddPath(path, g.self, g.privKey)
	if idx < 0 {
		return -1, mls.ErrRatchetTree
	}
	if g.merkleTree.Add(identityKey) != idx {
		return -1, mls.ErrMerkleTree
	}
	return idx, nil
}

func (g *GroupState) UpdateSelf(privKey []byte) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	var e crypto.GroupExponent
	if g.sukPub != nil {
		e = g.dh.Injection(g.dh.DH(g.sukPub, g.dh.Decode(privKey)))
	} else {
		e = g.dh.Decode(privKey)
	}
	if !g.ratchetTree.Update(g.self, e) {
		return mls.ErrRatchetTree
	}
	g.privKey = privKey	// update the private key for the later use
	// no need to update the merkle tree
	return nil
}

func (g *GroupState) UpdatePath(idx int, path [][]byte) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	var e crypto.GroupExponent
	if g.sukPub != nil {
		e = g.dh.Injection(g.dh.DH(g.sukPub, g.dh.Decode(g.privKey)))
	} else {
		e = g.dh.Decode(g.privKey)
	}
	if !g.ratchetTree.UpdatePath(idx, path, g.self, e) {
		return mls.ErrRatchetTree
	}
	return nil
}

func (g *GroupState) DeleteUser(idx int) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	_, junk, err := GenerateUserInitKey([]mls.CipherSuite{g.cipherSuite}, g.sig)
	if err != nil {
		return err
	}
	ek := junk[g.cipherSuite]
	if !g.ratchetTree.Update(idx, g.dh.Decode(ek)) {
		return mls.ErrRatchetTree
	}
	// do not touch the merkle tree
	return nil
}

func (g *GroupState) DeletePath(idx int, path [][]byte) error {
	// same as Update??
	return g.UpdatePath(idx, path)
}

func (g *GroupState) Copy() (*GroupState, error) {
	ng, err := NewGroupState(g.gid, g.cipherSuite, g.sig)
	if err != nil {
		return nil, err
	}
	ng.ratchetTree = g.ratchetTree.Copy()
	ng.merkleTree = g.merkleTree.Copy()
	ng.epoch = g.epoch
	ng.suk = g.suk		// copy of the reference
	ng.sukPub = g.sukPub
	copy(ng.messageSecret, g.messageSecret)
	copy(ng.initSecret, g.initSecret)
	ng.self = g.self
	ng.privKey = g.privKey	// reference is fine
	return ng, nil
}

func (g *GroupState) GetPath(leaf int) [][]byte {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	return g.ratchetTree.DirectPath(leaf)
}

func (g *GroupState) GetSelfPath() [][]byte {
	return g.GetPath(g.self)
}

func (g *GroupState) MessageKey() []byte {
	return g.messageSecret
}

func (g *GroupState) VerifyProof(value []byte, proof [][]byte, idx int) bool {
	// @@ what if the proof has been generated with a different hash...!?!?
	g.mutex.Lock()
	defer g.mutex.Unlock()
	return g.merkleTree.Verify(value, proof, idx)
}

func (g *GroupState) Proof() (int, [][]byte, error) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	proof, ok := g.merkleTree.Proof(g.self)
	if !ok {
		return -1, nil, mls.ErrMerkleTree
	}
	return g.self, proof, nil
}

func (g *GroupState) Epoch() uint32 {
	return g.epoch
}

func (g *GroupState) KeyScheduling(init bool, msg []byte, priorEpoch uint32) error {	// priorEpoch must be the same as the one in the message
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if priorEpoch != g.epoch {
		return ErrEpochOutOfSync
	}

	if init {
		for i, _ := range g.initSecret {
			g.initSecret[i] = 0
		}
	}
	g.epoch++

	if err := g.deriveSecret("msg", msg, g.messageSecret); err != nil {
		return err
	}
	suk := make([]byte, g.dh.Size())
	if err := g.deriveSecret("add", msg, suk); err != nil {
		return err
	}
	g.suk = g.dh.Derive(suk)
	if err := g.deriveSecret("init", msg, g.initSecret); err != nil {
		return err
	}
	return nil
}

func (g *GroupState) deriveSecret(label string, msg []byte, key []byte) error {
	info, err := packet.HkdfLabel(label, g.gid, g.epoch, msg, len(key))
	if err != nil {
		return err
	}
	hkdf := hkdf.New(g.hash, g.ratchetTree.RootKey()/*secret*/, g.initSecret/*salt*/, info)
	_, err = io.ReadFull(hkdf, key)
	return err
}

func (g *GroupState) ConstructGroupInitKey() (*mls.GroupInitKey, error) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	gik := &mls.GroupInitKey{
		Epoch: g.epoch,
		GroupSize: uint32(g.ratchetTree.Size()),
		GroupId: g.gid,
		Cipher: g.cipherSuite,
		AddKey: g.dh.Marshal(g.dh.DH(nil, g.suk)),
	}
	if frontier, ok := g.merkleTree.Frontier(); ok {
		gik.MerkleFrontier = frontier
	} else {
		return nil, mls.ErrMerkleTree
	}
	if frontier, ok := g.ratchetTree.Frontier(); ok {
		gik.RatchetFrontier = frontier
	} else {
		return nil, mls.ErrRatchetTree
	}
	return gik, nil
}

func GenerateUserInitKey(ciphers []mls.CipherSuite, sig *mls.Signature) (*mls.UserInitKey, map[mls.CipherSuite][]byte, error) {
	uik := &mls.UserInitKey{
		InitKeys: make(map[mls.CipherSuite][]byte),
	}
	privKeys := make(map[mls.CipherSuite][]byte)
	for _, cipher := range ciphers {
		g, err := mls.NewDH(cipher)
		if err != nil {	// not supported
			continue
		}
		// generate a random key pair
		pub, priv, err := g.GenerateKey()
		if err != nil {
			return nil, nil, err
		}
		uik.Ciphers = append(uik.Ciphers, cipher)
		uik.InitKeys[cipher] = g.Marshal(pub)
		privKeys[cipher] = g.Encode(priv)
	}
	uik.IdentityKey = sig.PublicKey()
	uik.SignatureAlgorithm = sig.Algorithm()
	tbs, err := packet.UserInitKeyTBS(uik)
	if err != nil {
		return nil, nil, err
	}
	s, err := sig.Sign(tbs)
	if err != nil {
		return nil, nil, err
	}
	uik.Signature = s
	return uik, privKeys, nil
}
