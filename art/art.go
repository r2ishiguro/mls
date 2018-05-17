// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package art

import (
	"github.com/r2ishiguro/mls/lbt"
	"github.com/r2ishiguro/mls/crypto"
)

type RatchetTree struct {
	tree *lbt.LeftBalancedTree
	g crypto.GroupOperation
	rootKey []byte
}

func New(g crypto.GroupOperation, frontier [][]byte, treeSize int) *RatchetTree {
	values := make([]interface{}, len(frontier))
	for i, value := range frontier {
		values[i] = g.Unmarshal(value)
	}
	return &RatchetTree{
		g: g,
		tree: lbt.New(values, treeSize),
	}
}

func (rt *RatchetTree) Add(leaf crypto.GroupExponent) int {
	rt.tree.Add(nil)
	// update the direct path from the added node
	idx := rt.tree.Size() - 1
	if !rt.Update(idx, leaf) {
		return -1
	}
	return idx
}

func (rt *RatchetTree) Update(idx int, leaf crypto.GroupExponent) bool {	// always takes the private key (or t(g^suk*pk))
	root, path := rt.calculate(idx, leaf)
	if root == nil {
		return false
	}
	rt.tree.Update(idx, path)
	rt.rootKey = root
	return true
}

func (rt *RatchetTree) AddPath(path [][]byte, self int, priv []byte) int {
	rt.tree.Add(nil)
	// update the direct path from the added node
	idx := rt.tree.Size() - 1
	if !rt.UpdatePath(idx, path, self, priv) {
		return -1
	}
	return idx
}

func (rt *RatchetTree) UpdatePath(idx int, path [][]byte, self int, priv []byte) bool {
	direct := make([]interface{}, len(path) + 1)	// +1 for the root
	for i, v := range path {
		direct[i] = rt.g.Unmarshal(v)
	}
	rt.tree.Update(idx, direct)
	root, _ := rt.calculate(self, rt.g.Decode(priv))
	if root == nil {
		return false
	}
	rt.rootKey = root
	return true
}

func (rt *RatchetTree) DirectPath(idx int) [][]byte {
	path := rt.tree.DirectPath(idx)
	res := make([][]byte, len(path))
	for i, v := range path {
		if v == nil {
			res[i] = nil
		} else {
			res[i] = rt.g.Marshal(v)
		}
	}
	return res
}

func (rt *RatchetTree) Frontier() ([][]byte, bool) {
	frontier, ok := rt.tree.Frontier()
	if !ok {
		return nil, ok
	}
	res := make([][]byte, len(frontier))
	for i, v := range frontier {
		if v == nil {
			res[i] = nil
		} else {
			res[i] = rt.g.Marshal(v)
		}
	}
	return res, true
}

func (rt *RatchetTree) RootKey() []byte {
	return rt.rootKey
}

func (rt *RatchetTree) Copy() *RatchetTree {
	return &RatchetTree{
		tree: rt.tree.Copy(),
		g: rt.g,
	}
}

func (rt *RatchetTree) Size() int {
	return rt.tree.Size()
}

func (rt *RatchetTree) calculate(idx int, leaf crypto.GroupExponent) ([]byte, []interface{}) {
	copath, ok := rt.tree.CoPath(idx)
	if !ok {
		return nil, nil
	}
	path := make([]interface{}, len(copath) + 1)
	x := leaf
	j := 0
	path[j] = rt.g.DH(nil, x); j++
	for _, node := range copath {
		e := rt.g.DH(node, x)
		x = rt.g.Injection(e)
		path[j] = rt.g.DH(nil, x); j++
	}
	return rt.g.Encode(x), path
}

func (rt *RatchetTree) TraceTree(f func(level int, size int, value interface{})) {
	lbt.TraceTree(rt.tree, f)
}
