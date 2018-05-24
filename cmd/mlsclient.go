// Copyright 2018, Oath Inc
// Licensed under the terms of the Apache 2.0 license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.

package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"
	"bufio"
	"time"
	"io"
	"io/ioutil"
	"log"
	"fmt"

	"github.com/r2ishiguro/mls"
	"github.com/r2ishiguro/mls/ds"
	"github.com/r2ishiguro/mls/protocol"
	"github.com/r2ishiguro/mls/crypto/aesgcm"
	"github.com/r2ishiguro/mls/auth/bftkvauth"
)

const (
	defaultDSAddr = "localhost:9897"
	defaultDirAddr = "localhost:9898"
	defaultMsgAddr = "localhost:9899"

	identityPubName = "idkey.pub"
	identityPrivName = "idkey.priv"
)

func main() {
	defaultPath := os.Getenv("HOME") + "/.gnupg/"
	keypathp := flag.String("home", defaultPath, "path to home")
	dsAddrp := flag.String("ds", defaultDSAddr, "ds server address")
	dirAddrp := flag.String("dir", defaultDirAddr, "directory service address")
	msgAddrp := flag.String("msg", defaultMsgAddr, "message service address")

	flag.Parse()
	keypath := *keypathp

	av := flag.Args()
	ac := len(av)
	if ac == 0 {
		flag.Usage()
		return
	}

	// use BFTKV as the auth server
	auth, err := bftkvauth.Open(keypath)
	if err != nil {
		log.Fatal(err)
	}
	uid := auth.UId()
	// choose ECDSA with P256 as the signature scheme
	sig, err := mls.NewSignature(mls.SignatureECDSA)
	if err != nil {
		log.Fatal(err)
	}
	// choose AES/GCM as the encryption scheme
	aead := aesgcm.NewAESGCM()
	// check if the identity key is already in the auth server
	pub, priv, err := readIdentityKey(keypath)
	if err != nil {
		// not registered yet -- generate a new pair of identity key and register it
		pub, priv, err = sig.Generate()
		if err != nil {
			log.Fatal(err)
		}
		if err := auth.Register(pub, uid); err != nil {
			log.Fatal(err)
		}
		if err := writeIdentityKey(keypath, pub, priv); err != nil {
			log.Fatal(err)
		}
	}
	sig.Initialize(pub, priv)

	dir := ds.NewDirectoryService(*dirAddrp)
	client := protocol.New(uid, dir, sig, auth, aead)

	switch (av[0]) {
	case "join":
		if ac < 2 {
			flag.Usage()
			return
		}
		echo(av[1], *dsAddrp, *msgAddrp, client)
	case "add":
		if ac < 2 {
			flag.Usage()
			return
		}
		add(av[1], av[2:], *dsAddrp, client)
	case "groups":	// list all groups
		for _, gid := range dir.ListGroups() {
			fmt.Printf("%s\n", gid)
		}
	case "users":	// list all users
		for _, uid := range dir.ListUsers() {
			fmt.Printf("%s\n", uid)
		}
	default:
		flag.Usage()
	}
	client.Close()
}

func startChannel(client *protocol.Protocol, addr string, gid string) *protocol.GroupChannel {
	if err := client.Connect(addr); err != nil {
		log.Fatal(err)
	}
	go func(client *protocol.Protocol) {
		err := client.Run()
		client.Close()
		if err != nil {
			log.Print(err)
		}
	}(client)

	// try to join an existing group
	channel, err := client.Join(gid)
	if err == protocol.ErrGroupNotFound {
		// the group doesn't exist, then create the new one
		channel, err = client.NewGroupChannelWithGID(gid, mls.CipherP256R1WithSHA256)
	}
	if err != nil {
		log.Fatalf("joining error: %s", err)
	}
	return channel
}

func echo(gid string, dsAddr string, msgAddr string, client *protocol.Protocol) {
	channel := startChannel(client, dsAddr, gid)
	sig := make(chan os.Signal, 3)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGABRT, syscall.SIGQUIT, syscall.SIGTERM)

	m, err := channel.NewMessage(msgAddr)
	if err != nil {
		log.Print(err)
		return
	}
	go func(m *protocol.Message) {
		r := bufio.NewReader(os.Stdin)
		for {
			text, err := r.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					log.Print(err)
				}
				break
			}
			m.Send([]byte(text))
		}
		sig <- syscall.SIGQUIT
	}(m)

	go func(m *protocol.Message) {
		for {
			msg, sender, err := m.Receive()
			if err != nil {
				if err != io.EOF {
					log.Print(err)
				}
				break
			}
			fmt.Printf("[%s => %s] %s\n", sender, client.UId(), string(msg))
		}
		sig <- syscall.SIGQUIT
	}(m)

	<- sig
	channel.Close()
}

func add(gid string, members []string, dsAddr string, client *protocol.Protocol) {
	channel := startChannel(client, dsAddr, gid)
	if err := channel.AddMembers(members); err != nil {
		log.Fatal(err)
	}
	// poll the status to check if it has finished
	for retry := 3; retry > 0; retry-- {
		time.Sleep(time.Second)
		fmt.Printf("%d...\n", retry)
		for _, uid := range channel.List() {
			fmt.Printf("%s\n", uid)
		}
	}
	channel.Close()
}

func readIdentityKey(path string) (pub, priv []byte, err error) {
	pub, err = ioutil.ReadFile(path + "/" + identityPubName)
	if err == nil {
		priv, err = ioutil.ReadFile(path + "/" + identityPrivName)
	}
	return
}

func writeIdentityKey(path string, pub, priv []byte) error {
	pubPath := path + "/" + identityPubName
	privPath := path + "/" + identityPrivName
	os.Rename(pubPath, pubPath + "~")
	os.Rename(privPath, privPath + "~")
	f, err := os.Create(pubPath)
	if err == nil {
		_, err = f.Write(pub)
		f.Close()
		if err == nil {
			if f, err = os.Create(privPath); err == nil {
				_, err = f.Write(priv)
				f.Close()
				if err == nil {
					os.Chmod(privPath, 0600)
				}
			}
		}
	}
	if err != nil {
		os.Rename(pubPath + "~", pubPath)
		os.Rename(privPath + "~", privPath)
	}
	return err
}
