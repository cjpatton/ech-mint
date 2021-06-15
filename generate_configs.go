// +build ignore

package main

import (
	"crypto/rand"
	"encoding/pem"
	"log"
	"os"

	"github.com/cjpatton/ech-mint"
	"github.com/cloudflare/circl/hpke"
)

func main() {
	version := ech.VersionECHDraft11

	x25519Template := ech.DefaultConfigTemplate()
	x25519Template.KemId = uint16(hpke.KEM_X25519_HKDF_SHA256)
	x25519Template.Version = version
	x25519Key, err := ech.GenerateKey(x25519Template, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	p256Template := ech.DefaultConfigTemplate()
	x25519Template.KemId = uint16(hpke.KEM_P256_HKDF_SHA256)
	p256Template.Version = version
	p256Key, err := ech.GenerateKey(p256Template, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	keys := []ech.ECHKey{*x25519Key, *p256Key}

	rawKeys, err := ech.MarshalECHKeys(keys)
	if err != nil {
		log.Fatal(err)
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

	configs := make([]ech.ECHConfig, 0, len(keys))
	for _, key := range keys {
		configs = append(configs, key.Config)
	}

	rawConfigs, err := ech.MarshalECHConfigs(configs)
	if err != nil {
		log.Fatal(err)
	}

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
