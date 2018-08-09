package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	"github.com/puiterwijk/p11sss/cmds"
)

type share struct {
	KeyCN string
	Parts []string
}

func encrypt(file string, threshold int, keyfilenames []string) {
	numshares := len(keyfilenames)

	certs := make([]*x509.Certificate, numshares)
	keys := make([]*rsa.PublicKey, numshares)
	for i := 0; i < len(keyfilenames); i++ {
		pemcts, err := ioutil.ReadFile(keyfilenames[i])
		if err != nil {
			panic(err)
		}
		pemblock, rest := pem.Decode(pemcts)
		if len(rest) != 0 {
			panic("Not full PEM file read")
		}
		if pemblock.Type != "CERTIFICATE" {
			panic("Not a certificate read")
		}
		cert, err := x509.ParseCertificate(pemblock.Bytes)
		if err != nil {
			panic(err)
		}
		certs[i] = cert
		rsakey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			panic("Non-RSA key found")
		}
		keys[i] = rsakey
	}
	val, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	vals, err := cmds.Encrypt(threshold, val, keys)
	if err != nil {
		panic(err)
	}

	shares := make([]share, len(keyfilenames))
	for i := 0; i < len(vals); i++ {
		cert := certs[i]
		parts := vals[i]

		sh := share{
			KeyCN: fmt.Sprintf("%s", cert.Subject),
			Parts: make([]string, len(parts)),
		}

		for j, part := range parts {
			sh.Parts[j] = hex.EncodeToString(part)
		}

		shares[i] = sh
	}

	shareJSON, err := json.Marshal(shares)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(shareJSON))
}

func main() {
	if len(os.Args) < 2 {
		panic("No operation specified")
	}
	if os.Args[1] == "encrypt" {
		if len(os.Args) < 4 {
			panic("Not enough arguments")
		}
		filename := os.Args[2]
		threshold, err := strconv.Atoi(os.Args[3])
		keyfilenames := os.Args[4:]

		if err != nil {
			log.Fatal("Failed to parse threshold")
		}

		if filename == "" || len(keyfilenames) < 1 {
			log.Fatal("Missing filename or key filenames")
		}
		encrypt(filename, threshold, keyfilenames)
	} else {
		log.Fatal("Invalid operation")
	}
}
