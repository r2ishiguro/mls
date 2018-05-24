// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package merkle

import (
	"hash"
	"bytes"

	"github.com/r2ishiguro/mls/lbt"
)

type MerkleTree struct {
	tree *lbt.LeftBalancedTree
	h func() hash.Hash
	rootHash []byte
}

func New(h func() hash.Hash, frontier [][]byte, treeSize int) *MerkleTree {
	var values []interface{}
	for _, value := range frontier {
		values = append(values, value)
	}
	return &MerkleTree{
		tree: lbt.New(values, treeSize),
		h: h,
	}
}

func (mt *MerkleTree) Add(leaf []byte) int {
	mt.tree.Add(nil)
	// update the direct path from the added node
	idx := mt.tree.Size() - 1
	root, path := mt.Calculate(idx, leaf)
	if root == nil {
		return -1
	}
	mt.tree.Update(idx, path)
	mt.rootHash = root
	return idx
}

func (mt *MerkleTree) Frontier() ([][]byte, bool) {
	path, ok := mt.tree.Frontier()
	if !ok {
		return nil, ok
	}
	res := make([][]byte, len(path))
	for i, v := range path {
		if v == nil {
			res[i] = nil
		} else {
			res[i] = v.([]byte)
		}
	}
	return res, true
}

func (mt *MerkleTree) Size() int {
	return mt.tree.Size()
}

func (mt *MerkleTree) Proof(idx int) ([][]byte, bool) {
	copath, ok := mt.tree.CoPath(idx)
	if !ok {
		return nil, ok
	}
	res := make([][]byte, len(copath) + 1)
	v := mt.tree.Leaf(idx)
	if v == nil {
		res[0] = nil
	} else {
		res[0] = v.([]byte)
	}
	for i, v := range copath {
		if v == nil {
			res[i+1] = nil
		} else {
			res[i+1] = v.([]byte)
		}
	}
	return res, true
}

func (mt *MerkleTree) Copy() *MerkleTree {
	return &MerkleTree{
		tree: mt.tree.Copy(),
		h: mt.h,
		rootHash: mt.rootHash,
	}
}

func (mt *MerkleTree) Verify(value []byte, proof [][]byte, idx int) bool {
	if len(proof) == 0 {
		return false
	}
	val, path := calculate(idx, value, proof[1:], mt.Size(), mt.h())
	return bytes.Equal(val, mt.rootHash) && bytes.Equal(path[0].([]byte), proof[0])
}

func (mt *MerkleTree) Calculate(idx int, leaf []byte) ([]byte, []interface{}) {
	proof, ok := mt.Proof(idx)	// want copath
	if !ok || len(proof) == 0 {
		return nil, nil
	}
	return calculate(idx, leaf, proof[1:], mt.Size(), mt.h())
}

func calculate(idx int, leaf []byte, copath [][]byte, size int, f hash.Hash) ([]byte, []interface{}) {
	rightmost := size - 1
	path := make([]interface{}, len(copath) + 1)
	if leaf == nil {
		f.Write([]byte{0})
	} else {
		f.Write([]byte{1})
		f.Write(leaf)
	}
	v := f.Sum(nil)
	j := 0
	path[j] = v; j++
	for _, node := range copath {
		var left, right []byte
		if idx % 2 == 0 && idx != rightmost {
			left = v
			right = node
		} else {
			left = node
			right = v
		}
		f.Reset()
		f.Write([]byte{2})
		f.Write(left)
		f.Write(right)
		v = f.Sum(nil)
		path[j] = v; j++
		idx /= 2
		rightmost /= 2
	}
	return v, path
}


func (mt *MerkleTree) TraceTree(f func(level int, size int, value interface{})) {
	lbt.TraceTree(mt.tree, f)
}
