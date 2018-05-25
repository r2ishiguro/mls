// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package protocol

import (
	"testing"
	"bytes"
	"fmt"

	"github.com/r2ishiguro/mls"
	"github.com/r2ishiguro/mls/crypto"
	"github.com/r2ishiguro/mls/packet"
)

func TestGenerateUserInitKey(t *testing.T) {
	uik, _, err := generateUIK()
	if err != nil {
		t.Fatal(err)
	}

	// veriy the generated UIK
	sig, err := mls.NewSignature(uik.SignatureAlgorithm)
	if err != nil {
		t.Fatal(err)
	}
	sig.Initialize(uik.IdentityKey, nil)
	tbs, err := packet.UserInitKeyTBS(uik)
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Verify(tbs, uik.Signature); err != nil {
		t.Fatal(err)
	}
}

func TestGroupState(t *testing.T) {
	sig, err := mls.NewSignature(mls.SignatureECDSA)
	if err != nil {
		t.Fatalf("unsupported signature scheme: %d", mls.SignatureECDSA)
	}
	pub, priv, err := sig.Generate()
	if err != nil {
		t.Fatal(err)
	}
	sig.Initialize(pub, priv)
	g, err := NewGroupState("test GID", mls.CipherP256R1WithSHA256, sig)
	if err != nil {
		t.Fatal(err)
	}
	selfUIK, selfKeys, err := generateUIK()
	if err != nil {
		t.Fatal(err)
	}
	priv = selfKeys[mls.CipherP256R1WithSHA256]
	if _, err := g.AddSelf(priv, selfUIK.IdentityKey); err != nil {
		t.Fatal(err)
	}
	for nusers := 6; nusers > 0; nusers-- {
		uik, _, err := generateUIK()
		if err != nil {
			t.Fatal(err)
		}
		idx, err := g.AddUser(uik)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("[%d] root = %x\n", idx, g.ratchetTree.RootKey())
	}

	//
	// participate a new user in a new group
	//
	gik, err := g.ConstructGroupInitKey()
	if err != nil {
		t.Fatal(err)
	}
	uik, privKeys, err := generateUIK()
	ng, err := NewGroupStateWithGIK(gik, sig)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("=== frontier ===\n")
	for _, f := range gik.RatchetFrontier {
		fmt.Printf("%x\n", f)
	}
	idx, err := ng.AddSelf(privKeys[gik.Cipher], uik.IdentityKey)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("=== ng ===\n")
	ng.ratchetTree.TraceTree(func(level int, size int, value interface{}) {
		fmt.Printf("[%d] %x (%d)\n", level, ng.dh.Marshal(value.(crypto.GroupExponent)), size)
	})
	path := ng.GetPath(idx)
	idx, proof, err := ng.Proof()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("path:\n")
	for i, p := range path {
		fmt.Printf(" [%d] %x\n", i, p)
	}

	// add the new user to 'g'
	g2, err := g.Copy()
	if err != nil {
		t.Fatal(err)
	}
	idx, err = g.AddPath(path, uik.IdentityKey)
	if err != nil {
		t.Fatal(err)
	}
	idx2, err := g2.AddUser(uik)
	if err != nil {
		t.Fatal(err)
	}
	// g2 must be equal to g
	if idx != idx2 {
		t.Fatal(ErrInconsistentPath)
	}
	fmt.Printf("=== g ===\n")
	g.ratchetTree.TraceTree(func(level int, size int, value interface{}) {
		if value == nil {
			fmt.Printf("[%d] nil (%d)\n", level, size)
		} else {
			fmt.Printf("[%d] %x (%d)\n", level, g.dh.Marshal(value.(crypto.GroupExponent)), size)
		}
	})

	if !bytes.Equal(g.ratchetTree.RootKey(), ng.ratchetTree.RootKey()) || !bytes.Equal(g.ratchetTree.RootKey(), g2.ratchetTree.RootKey()) {
		t.Fatalf("root key mismatach")
	}

	// verify the Merkle proof
	if !g.VerifyProof(uik.IdentityKey, proof, idx) {
		t.Fatalf("failed to verify the proof")
	}
	if !ng.VerifyProof(uik.IdentityKey, proof, idx) {
		t.Fatalf("failed to verify the proof")
	}

	msg := []byte("msg...")
	g.KeyScheduling(false, msg, 0)
	ng.KeyScheduling(false, msg, 0)
	if !bytes.Equal(g.MessageKey(), ng.MessageKey()) {
		t.Fatalf("message key mismatch")
	}
}

func generateUIK() (*mls.UserInitKey, map[mls.CipherSuite][]byte, error) {
	ciphers := []mls.CipherSuite{	// it's not guaranteed to generate keys for all ciphers
		mls.CipherX25519WithSHA256,
		mls.CipherP256R1WithSHA256,
	}
	sig, err := mls.NewSignature(mls.SignatureECDSA)
	if err != nil {
		return nil, nil, err
	}
	pub, priv, err := sig.Generate()
	if err != nil {
		return nil, nil, err
	}
	sig.Initialize(pub, priv)
	return GenerateUserInitKey(ciphers, sig)
}
