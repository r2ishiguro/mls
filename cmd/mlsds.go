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
	addrp := flag.String("addr", "localhost:9897", "server address")
	dirAddrp := flag.String("dir", "localhost:9898", "directory service address")
	msgAddrp := flag.String("msg", "localhost:9899", "directory service address")
	portRangep := flag.String("port", "9900-9999", "port range")
	flag.Parse()

	ks := simplekv.New()
	var portRange [2]int
	fmt.Scanf(*portRangep, "%d-%d", &portRange[0], &portRange[1])
	server := ds.NewServer(*addrp, *dirAddrp, *msgAddrp, portRange, ks)
	go func(server *ds.Server) {
		if err := server.Start(); err != nil {
			log.Fatal(err)
			return
		}
	}(server)

	// wait for a signal
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGABRT, syscall.SIGQUIT, syscall.SIGTERM)
	<-ch

	server.Close()
}
