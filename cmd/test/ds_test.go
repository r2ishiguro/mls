// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package ds

import (
	"testing"
	"time"

	"github.com/r2ishiguro/mls/ds"
	"github.com/r2ishiguro/mls/ds/keystore/simplekv"
)

const (
	deliveryAddress = "localhost:9898"
	directoryAddress = "localhost:9899"
	messageAddress = "localhost:9900"
)

var (
	channelPorts = [2]int{9901, 9999}
)

func TestDS(t *testing.T) {
	server := ds.NewServer(deliveryAddress, directoryAddress, messageAddress, channelPorts, simplekv.New())
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Second)
}
