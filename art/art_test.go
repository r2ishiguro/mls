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
		k, _ := rt.calculate(i, rt.g.Encode(leaves[i].e))
		if !bytes.Equal(rootKey, k) {
			t.Fatalf("the root key mismatch")
		}
	}
	frontier, ok := rt.tree.Frontier()
	if !ok {
		t.Fatalf("couldn't get frontier")
	}
	fmt.Printf("=== Frontier ===\n")
	printPath(rt.g, frontier)
}

func generateTree(rt *RatchetTree, n int) (leaves []*node, err error) {
	leaves = make([]*node, n)
	fmt.Printf("=== leaves ===\n")
	for i := 0; i < n; i++ {
		b, e, err := rt.g.GenerateKey()
		if err != nil {
			return nil, err
		}
		leaves[i] = &node{b, e}
		idx := rt.Add(e)
		fmt.Printf("[%d] %x\n", idx, rt.g.Marshal(b))
	}
	fmt.Printf("=== tree ===\n")
	lbt.TraceTree(rt.tree, func(level int, size int, value interface{}) {
		fmt.Printf("[%d] %x (%d)\n", level, rt.g.Marshal(value.(crypto.GroupExponent)), size)
	})
	return leaves, nil
}

func printPath(g crypto.GroupOperation, path []interface{}) {
	for i, p := range path {
		if p == nil {
			fmt.Printf("[%d] nil\n", i)
		} else {
			v := g.Marshal(p.(crypto.GroupElement))
			fmt.Printf("[%d] %x\n", i, v)
		}
	}
}
