// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"fmt"

	"github.com/r2ishiguro/mls/ds"
	"github.com/r2ishiguro/mls/ds/keystore/simplekv"
)

func main() {
	addrp := flag.String("addr", ":9897", "server address")
	dirAddrp := flag.String("dir", ":9898", "directory service address")
	msgAddrp := flag.String("msg", ":9899", "message service address")
	portRangep := flag.String("port", "9900-9999", "message port range")
	flag.Parse()

	ks := simplekv.New()
	var portRange [2]int
	fmt.Sscanf(*portRangep, "%d-%d", &portRange[0], &portRange[1])
	server := ds.NewServer(*addrp, *dirAddrp, *msgAddrp, portRange, ks)
	if err := server.Start(); err != nil {
		log.Fatal(err)
		return
	}

	// wait for a signal
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGABRT, syscall.SIGQUIT, syscall.SIGTERM)
	<-ch

	server.Close()
}
