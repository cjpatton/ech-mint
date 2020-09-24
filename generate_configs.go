// Copyright 2020 Cloudflare, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// +build ignore

package main

import (
	"crypto/rand"
	"encoding/pem"
	"log"
	"os"

	"github.com/cjpatton/ech-mint"
)

func main() {
	version := ech.VersionECHDraft08

	x25519Template := ech.DefaultConfigTemplate()
	x25519Template.KemId = ech.HPKE_KEM_DHKEM_X25519_HKDF_SHA256
	x25519Template.Version = version
	x25519Key, err := ech.GenerateKey(x25519Template, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	p256Template := ech.DefaultConfigTemplate()
	p256Template.KemId = ech.HPKE_KEM_DHKEM_P256_HKDF_SHA256
	p256Template.Version = version
	p256Key, err := ech.GenerateKey(p256Template, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	rawKeys := make([]byte, 0)
	rawConfigs := make([]byte, 0)
	for _, key := range []*ech.Key{x25519Key, p256Key} {
		rawKey, err := key.Marshal()
		if err != nil {
			log.Fatal(err)
		}
		rawKeys = append(rawKeys, rawKey...)

		rawConfig, err := key.Config.Marshal()
		if err != nil {
			log.Fatal(err)
		}
		rawConfigs = append(rawConfigs, rawConfig...)
	}

	keysOut, err := os.OpenFile("keys.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer keysOut.Close()

	if err = pem.Encode(keysOut, &pem.Block{Type: "ECH KEYS", Bytes: rawKeys}); err != nil {
		log.Fatal(err)
	}

	log.Println("wrote keys.pem")

	configsOut, err := os.Create("configs.pem")
	if err != nil {
		log.Fatal(err)
	}
	defer configsOut.Close()

	if err = pem.Encode(configsOut, &pem.Block{Type: "ECH CONFIGS", Bytes: rawConfigs}); err != nil {
		log.Fatal(err)
	}

	log.Println("wrote configs.pem")
}
