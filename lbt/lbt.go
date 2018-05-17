// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package lbt

type node struct {
	value interface{}
	size int
	left, right *node
}

type LeftBalancedTree struct {
	root *node
}

func New(frontier []interface{}, size int) *LeftBalancedTree {
	lbt := &LeftBalancedTree{}
	if frontier != nil {
		lbt.Construct(frontier, size)
	}
	return lbt
}

//
// frontier = copath from the last leaf + 1
//
func (lbt *LeftBalancedTree) Construct(frontier []interface{}, size int) {
	if len(frontier) > 0 {
		lbt.root = setFrontier(frontier, size)
	}
}

func setFrontier(frontier []interface{}, size int) *node {
	if len(frontier) == 1 {
		return &node{frontier[0], size, nil, nil}
	}
	leftSize := exp(size)
	return &node{
		value: nil,
		size: size,
		left: &node{frontier[len(frontier)-1], leftSize, nil, nil},
		right: setFrontier(frontier[:len(frontier)-1], size - leftSize),
	}
}

func exp(n int) int {
	// find the closest 2^e
	t := 1
	for t*2 < n {
		t *= 2
	}
	return t
}

func (lbt *LeftBalancedTree) Add(value interface{}) {
	lbt.root = addNode(lbt.root, value)
}

func addNode(root *node, value interface{}) *node {
	if root == nil {
		return &node{value, 1, nil, nil}
	}
	leftSize := 0
	if root.left != nil {
		leftSize = root.left.size
	}
	rightSize := 0
	if root.right != nil {
		rightSize = root.right.size
	}
	if leftSize > rightSize {	// can add the node to the right tree
		root.right = addNode(root.right, value)
		root.size++
		return root
	} else {
		return &node{
			value: nil,
			size: root.size + 1,
			left: root,
			right: &node{value, 1, nil, nil},
		}
	}
}

func (lbt *LeftBalancedTree) Update(leaf int, path []interface{}) {
	updateNode(lbt.root, leaf, path)
}

func updateNode(root *node, leaf int, path []interface{}) {
	if root == nil || len(path) == 0 {
		return
	}
	root.value = path[len(path) - 1]
	if root.left == nil {
		// no-op
	} else if leaf < root.left.size {
		updateNode(root.left, leaf, path[:len(path)-1])
	} else if root.right != nil {
		updateNode(root.right, leaf - root.left.size, path[:len(path)-1])
	}
}

func (lbt *LeftBalancedTree) Size() int {
	return lbt.root.size
}

func (lbt *LeftBalancedTree) DirectPath(leaf int) []interface{} {
	path := directPath(lbt.root, leaf)
	if len(path) > 0 {
		path = path[:len(path)-1]	// remove the root
	}
	return path
}

func directPath(root *node, leaf int) []interface{} {
	if root == nil {
		return nil
	} else if root.left == nil {	// leaf should be 1
		return []interface{}{root.value}
	} else if leaf < root.left.size {
		return append(directPath(root.left, leaf), root.value)
	} else if root.right != nil {
		return append(directPath(root.right, leaf - root.left.size), root.value)
	}
	// should not reach here...
	return nil
}

func (lbt *LeftBalancedTree) Leaf(idx int) interface{} {
	var leaf interface{}
	trace(lbt.root, idx, func(n *node) {
		if n.left == nil {
			leaf = n.value
		}
	})
	return leaf
}

func trace(root *node, leaf int, cb func(n *node)) {
	if root == nil {
		return
	}
	cb(root)
	if root.left == nil {
		return
	} else if leaf < root.left.size {
		trace(root.left, leaf, cb)
	} else if root.right != nil {
		trace(root.right, leaf - root.left.size, cb)
	}
}

func (lbt *LeftBalancedTree) CoPath(leaf int) ([]interface{}, bool) {
	return coPath(lbt.root, leaf)
}

func coPath(root *node, leaf int) (path []interface{}, ok bool) {
	if root == nil {	// only happens when the tree hasn't been initialized yet
		return nil, true
	}
	if root.size == 1 {	// reached a leaf
		if leaf != 0 {
			panic("corrupted")
		}
		return nil, true
	}
	if root.left == nil || root.right == nil {	// cannot get the copath
		return nil, false	// not completed
	}
	var co interface{}
	if leaf < root.left.size {
		path, ok = coPath(root.left, leaf)
		co = root.right.value
	} else {
		path, ok = coPath(root.right, leaf - root.left.size)
		co = root.left.value
	}
	if !ok {
		return nil, false
	}
	return append(path, co), true
}

func (lbt *LeftBalancedTree) Frontier() ([]interface{}, bool) {
	t := lbt.Copy()
	t.Add(nil)
	return t.CoPath(t.Size() - 1)
}

func (lbt *LeftBalancedTree) Copy() *LeftBalancedTree {
	return &LeftBalancedTree{copyTree(lbt.root)}
}

func copyTree(root *node) *node {
	if root == nil {
		return nil
	}
	return &node{
		value: root.value,
		size: root.size,
		left: copyTree(root.left),
		right: copyTree(root.right),
	}
}

func TraceTree(lbt *LeftBalancedTree, f func(level int, size int, value interface{})) {
	traceTree(lbt.root, 0, f)
}

func traceTree(n *node, level int, f func(level int, size int, value interface{})) {
	if n == nil {
		return
	}
	f(level, n.size, n.value)
	traceTree(n.left, level + 1, f)
	traceTree(n.right, level + 1, f)
}
