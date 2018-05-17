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
	ratchetTree *art.RatchetTree	// keep the shape of two trees the same
	merkleTree *merkle.MerkleTree
	epoch uint32
	suk crypto.GroupExponent			// add key (private)
	messageSecret []byte		// message master secret
	initSecret []byte
	self int			// the leaf index
	privKey []byte			// the private key corresponding to the leaf index
	mutex sync.Mutex
	sig *mls.Signature
	dh crypto.GroupOperation
	hash func() hash.Hash
}

func NewGroupState(gid string, sig *mls.Signature) *GroupState {
	return &GroupState{
		gid: gid,
		sig: sig,
	}
}

func (g *GroupState) Initialize(cipher mls.CipherSuite, privKey []byte, identityKey []byte) (int, error) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if err := g.initialize(cipher); err != nil {
		return -1, err
	}
	g.ratchetTree = art.New(g.dh, nil, 0)
	g.merkleTree = merkle.New(g.hash, nil, 0)
	g.epoch = 0

	// add the self node
	idx := g.ratchetTree.Add(g.dh.Decode(privKey))
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

func (g *GroupState) InitializeWithGIK(gik *mls.GroupInitKey, privKey []byte, identityKey []byte) (int, error) {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if err := g.initialize(gik.Cipher); err != nil {
		return -1, err
	}
	g.ratchetTree = art.New(g.dh, gik.RatchetFrontier, int(gik.GroupSize))
	g.merkleTree = merkle.New(g.hash, gik.MerkleFrontier, int(gik.GroupSize))
	g.epoch = gik.Epoch

	// add the self node
	sukPub := g.dh.Unmarshal(gik.AddKey)
	idx := g.ratchetTree.Add(g.dh.Injection(g.dh.DH(sukPub, g.dh.Decode(privKey))))
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

func (g *GroupState) initialize(cipher mls.CipherSuite) (err error) {
	dh, err := mls.NewDH(cipher)
	if err != nil {
		return err
	}
	hash, err := mls.NewHash(cipher)
	if err != nil {
		return err
	}
	g.cipherSuite = cipher
	g.dh = dh
	g.hash = hash
	g.initSecret = make([]byte, g.hash().Size())
	g.messageSecret = make([]byte, g.hash().Size())	// the message encryption key size = hash size
	_, g.suk, err = dh.GenerateKey()
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

func (g *GroupState) UpdateSelf(privKeys [][]byte) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if !g.ratchetTree.Update(g.self, g.dh.Decode(privKeys[g.cipherSuite])) {	// use the private key *as-is* (not with SUK)
		return mls.ErrRatchetTree
	}
	// no need to update the merkle tree
	return nil
}

func (g *GroupState) UpdatePath(path [][]byte) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if !g.ratchetTree.UpdatePath(g.self, path, g.self, g.privKey) {
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

func (g *GroupState) DeletePath(path [][]byte) error {
	// same as Update??
	return g.UpdatePath(path)
}

func (g *GroupState) Copy() (*GroupState, error) {
	ng := NewGroupState(g.gid, g.sig)
	if err := ng.initialize(g.cipherSuite); err != nil {
		return nil, err
	}
	ng.ratchetTree = g.ratchetTree.Copy()
	ng.merkleTree = g.merkleTree.Copy()
	ng.epoch = g.epoch
	ng.suk = g.suk	// copy of the reference
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

func (g *GroupState) Proof() (int, [][]byte) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	proof, ok := g.merkleTree.Proof(g.self)
	if !ok {
		return -1, nil
	}
	return g.self, proof
}

func (g *GroupState) Epoch() uint32 {
	return g.epoch
}

func (g *GroupState) KeyScheduling(init bool, msg []byte) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

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
