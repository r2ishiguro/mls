// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package art

import (
	"testing"
	"bytes"
	"crypto/elliptic"
	"fmt"

	"github.com/r2ishiguro/mls/crypto"
	"github.com/r2ishiguro/mls/crypto/ecdh"
	"github.com/r2ishiguro/mls/lbt"
)

type node struct {
	b crypto.GroupElement
	e crypto.GroupExponent
	idx int
}

func TestFrontier(t *testing.T) {
	curve := elliptic.P256()
	g := ecdh.New(curve)
	var frontier [3][]byte
	for i := 0; i < 3; i++ {
		b, _, err := g.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		frontier[i] = g.Marshal(b)
	}
	_, priv, err := g.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	rt := New(g, frontier[:], 7)
	rt.Add(priv)
	root := rt.RootKey()
	fmt.Printf("%x\n", root)
}

func TestRootKey(t *testing.T) {
	n := 7
	curve := elliptic.P256()
	g := ecdh.New(curve)
	rt := New(g, nil, 0)
	leaves, err := generateTree(rt, n)
	if err != nil {
		t.Fatal(err)
	}
	rootKey := rt.RootKey()
	for i := 0; i < n; i++ {
		k, _ := rt.calculate(leaves[i].idx, rt.g.Encode(leaves[i].e))
		if !bytes.Equal(rootKey, k) {
			t.Fatalf("the root key mismatch")
		}
	}
	frontier, ok := rt.Frontier()
	if !ok {
		t.Fatalf("couldn't get frontier")
	}
	fmt.Printf("=== Frontier ===\n")
	printPath(rt.g, frontier)

	//
	// with the frontier, we add a new leaf and update the original tree with the new path
	// now create a new node with the frontier
	//
	nt := New(g, frontier, rt.Size())
	// add a leaf
	_, e, err := g.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	idx := nt.Add(e)
	if idx < 0 {
		t.Fatal("Add() failed")
	}
	path := nt.DirectPath(idx)
	// update the original tree with the new path
	for i := 0; i < n; i++ {
		tt := rt.Copy()
		nidx := tt.AddPath(path, leaves[i].idx, leaves[i].e)
		if nidx != idx {
			t.Fatalf("AddPath() failed: %d vs %d", nidx, idx)
		}
		// now check if we've got the same root key
		if !bytes.Equal(nt.RootKey(), tt.RootKey()) {
			t.Fatalf("the new root key mismatch: [%d] %x vs %x", i, rt.RootKey(), tt.RootKey())
		}
	}
}

func generateTree(rt *RatchetTree, n int) (leaves []*node, err error) {
	leaves = make([]*node, n)
	fmt.Printf("=== leaves ===\n")
	for i := 0; i < n; i++ {
		b, e, err := rt.g.GenerateKey()
		if err != nil {
			return nil, err
		}
		idx := rt.Add(e)
		leaves[i] = &node{b, e, idx}
		fmt.Printf("[%d] %x\n", idx, rt.g.Marshal(b))
	}
	fmt.Printf("=== tree ===\n")
	lbt.TraceTree(rt.tree, func(level int, size int, value interface{}) {
		fmt.Printf("[%d] %x (%d)\n", level, rt.g.Marshal(value.(crypto.GroupExponent)), size)
	})
	return leaves, nil
}

func printPath(g crypto.GroupOperation, path [][]byte) {
	for i, p := range path {
		if p == nil {
			fmt.Printf("[%d] nil\n", i)
		} else {
			fmt.Printf("[%d] %x\n", i, p)
		}
	}
}
