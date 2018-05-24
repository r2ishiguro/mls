// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package merkle

import (
	"testing"
	"crypto/sha256"
	"fmt"

	"github.com/r2ishiguro/mls/lbt"
)

func TestVerify(t *testing.T) {
	n := 7
	mt := New(sha256.New, nil, 0)
	for i := 0; i < n; i++ {
		val := []byte{byte(i)}
		idx := mt.Add(val)
		if idx < 0 {
			t.Fatalf("failed to add")
		}
		for j := 0; j <= idx; j++ {
			proof, ok := mt.Proof(j)
			if !ok {
				t.Fatalf("failed to get a proof")
			}
			fmt.Printf("Proof[%d]\n", j)
			for k := 0; k < len(proof); k++ {
				fmt.Printf("  %x\n", proof[k])
			}
			if !mt.Verify([]byte{byte(j)}, proof, j) {
				t.Fatalf("failed to verify: %d:%d", i, j)
			}
		}
	}
}

func TestFrontier(t *testing.T) {
	n := 7
	mt := New(sha256.New, nil, 0)
	mt.Add([]byte{byte(0)})
	for i := 1; i < n; i++ {
		frontier, ok := mt.Frontier()
		if !ok {
			t.Fatalf("failed to get a frontier")
		}
		size := mt.Size()
		val := []byte{byte(i)}
		mt.Add(val)
		proof, ok := mt.Proof(0)
		if !ok {
			t.Fatalf("failed to get a proof")
		}
		fmt.Printf("=== mt ===\n")
		lbt.TraceTree(mt.tree, func(level int, size int, value interface{}) {
			fmt.Printf("[%d] %x (%d)\n", level, value.([]byte), size)
		})

		fmt.Printf("<%d> frontier = %x, proof = %x\n", i, frontier, proof)
		nt := New(sha256.New, frontier, size)
		nt.Add(val)
		fmt.Printf("=== nt ===\n")
		lbt.TraceTree(nt.tree, func(level int, size int, value interface{}) {
			fmt.Printf("[%d] %x (%d)\n", level, value.([]byte), size)
		})

		if !nt.Verify([]byte{byte(0)}, proof, 0) {
			t.Errorf("failed to verify: %d", i)
		}
	}
}
