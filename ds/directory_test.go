// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package ds

import (
	"testing"
	"bytes"
	"fmt"

	"github.com/r2ishiguro/mls/ds/keystore/simplekv"
)

const (
	dirAddr = "localhost:9897"
	testUID = "foo@bar.com"
)

var (
	testUIK = []byte("test uik")
)

func TestDirectory(t *testing.T) {
	dir, err := startDirectoryServer(dirAddr, simplekv.New())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.stop()

	client := NewDirectoryService(dirAddr);
	if err := client.register(testUID, testUIK, directoryDataTypeUser); err != nil {
		t.Fatal(err)
	}
	res, err := client.lookup(testUID, directoryDataTypeUser)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res, testUIK) {
		t.Fatalf("data mismatch")
	}

	list := client.ListUsers()
	for _, l := range list {
		fmt.Printf("%s\n", l)
	}

	if err := client.DeleteUser(testUID); err != nil {
		t.Fatal(err)
	}
	res, err = client.lookup(testUID, directoryDataTypeUser)
	if err != nil {
		t.Fatal(err)
	}
	if res != nil && len(res) != 0 {
		t.Fatalf("couldn't delete user: %v", res)
	}
}
