# mls
An implementation of MLS (Messaging Layer Security) https://tools.ietf.org/html/draft-barnes-mls-protocol-00

This implementation uses BFTKV (https://github.com/yahoo/bftkv) as the Authentication Service defined in the architecture document (https://datatracker.ietf.org/doc/draft-omara-mls-architecture). See documents in https://github.com/yahoo/bftkv/docs for details.

## Setup
1. Install BFTKV
	1. `go get -u github.com/yahoo/bftkv`
	1. Install [GnuPG 2.x](https://www.gnupg.org/download/index.en.html)
	1. Run `setup.sh` in bftkv/scripts
	1. Run a BFTKV cluster `cd bftkv/scripts/run; ../run.sh`
	1. Build a command line tool cd bftkv/cmd/bftrw; go get .`
1. Run Delivery Service (mlsds)
	1. Build the server `cd mls/cmd; go build mlsds.go`
	1. `mlsds`
1. Setup a key pair
	1. `cd bftkv/scripts; gen.sh -uid foo@bar.com key`
	1. `mv key mls/cmd`
	1. `bftrw -path $GOPATH/src/github.com/yahoo/bftrw/scripts/run/keys -key key register`
1. Run a MLS client
	1. Build mlsclient `cd mls/cmd; go build mlsclient.go`
	1. `mlsclient -home key join mygroup`

You can make as many keys as you want for the mls client, by repeating the step 3 and 4.

## License
Copyright 2018, Oath Inc

Licensed under the terms of the Apache license. See LICENSE file in https://github.com/r2ishiguro/mls for terms.
