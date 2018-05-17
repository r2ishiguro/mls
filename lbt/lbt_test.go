// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package lbt

import (
	"testing"
	"fmt"
)

type testItem struct {
	frontier []int
	size int
}

var testVectors = []testItem{
	{[]int{1, 2, 3}, 7},
}

func TestLBT(t *testing.T) {
	for _, v := range testVectors {
		values := make([]interface{}, len(v.frontier))
		for i := 0; i < len(values); i++ {
			values[i] = v.frontier[i]
		}
		lbt := New(values, v.size)
		lbt.Add(999)
		path := lbt.DirectPath(v.size)	// we have added one node
		fmt.Printf("=== DirectPath ===\n")
		printPath(path)
		copath, ok := lbt.CoPath(v.size)
		if !ok {
			t.Fatalf("couldn't get copath")
		}
		fmt.Printf("=== CoPath ===\n")
		printPath(copath)
	}
}

func printPath(path []interface{}) {
	for _, v := range path {
		if v == nil {
			fmt.Printf("nil ")
		} else {
			fmt.Printf("%d ", v.(int))
		}
	}
	fmt.Printf("\n")
}
