#!/bin/sh
go mod init notary
go get github.com/bwesterb/go-ristretto@b51b4774df9150ea7d7616f76e77f745a464bbe3
go get github.com/roasbeef/go-go-gadget-paillier@14f1f86b60008ece97b6233ed246373e555fc79f
go get golang.org/x/crypto/blake2b
go get golang.org/x/crypto/salsa20/salsa
go build -o notary
