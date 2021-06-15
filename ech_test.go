package ech

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

func TestECHKeysSerialization(t *testing.T) {
	want := genTestKeys(t)

	rawKeys, err := MarshalECHKeys(want)
	if err != nil {
		t.Fatal(err)
	}

	got, err := UnmarshalECHKeys(rawKeys)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != len(want) {
		t.Fatalf("incorrect length: got %d; want %d", len(got), len(want))
	}

	for i := range got {
		if !bytes.Equal(got[i].rawSecretKey, want[i].rawSecretKey) {
			t.Errorf("incorrect rawSecretKey: got %v; want %v", got[i].rawSecretKey, want[i].rawSecretKey)
		}

		testPrivateKeysEqual(t, got[i].sk, want[i].sk)
		testConfigsEqual(t, got[i].Config, want[i].Config)
	}
}

func TEstECHConfigsSerialization(t *testing.T) {
	keys := genTestKeys(t)

	want := make([]ECHConfig, 0)
	for _, key := range keys {
		want = append(want, key.Config)
	}

	rawConfigs, err := MarshalECHConfigs(want)
	if err != nil {
		t.Fatal(err)
	}

	got, err := UnmarshalECHConfigs(rawConfigs)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != len(want) {
		t.Fatalf("incorrect length: got %d; want %d", len(got), len(want))
	}

	for i := range got {
		testConfigsEqual(t, got[i], want[i])
	}
}

func genTestKeys(t *testing.T) []ECHKey {
	template := DefaultConfigTemplate()
	template.KemId = uint16(hpke.KEM_X25519_HKDF_SHA256)
	template.ignoredExtensions = []byte("raw ECHConfigContents.extensions")
	x25519Key, err := GenerateKey(template, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template.KemId = uint16(hpke.KEM_P256_HKDF_SHA256)
	template.ignoredExtensions = nil
	p256Key, err := GenerateKey(template, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return []ECHKey{*x25519Key, *p256Key}
}

func testPrivateKeysEqual(t *testing.T, a, b kem.PrivateKey) {
	rawA, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	rawB, err := b.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(rawA, rawB) {
		t.Error("incorrect private key")
	}
}

func testPublicKeysEqual(t *testing.T, a, b kem.PublicKey) {
	rawA, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	rawB, err := b.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(rawA, rawB) {
		t.Error("incorrect public key")
	}
}

func testConfigsEqual(t *testing.T, a, b ECHConfig) {
	testPublicKeysEqual(t, a.pk, b.pk)

	if a.version != b.version {
		t.Errorf("incorrect version: got %d; want %d", a.version, b.version)
	}

	if a.configId != b.configId {
		t.Errorf("incorrect configId: got %d; want %d", a.configId, b.configId)
	}

	if !bytes.Equal(a.rawPublicName, b.rawPublicName) {
		t.Errorf("incorrect rawPublicName: got %s; want %s", a.rawPublicName, b.rawPublicName)
	}

	if !bytes.Equal(a.rawPublicKey, b.rawPublicKey) {
		t.Errorf("incorrect rawPublicKey: got %s; want %s", a.rawPublicKey, b.rawPublicKey)
	}

	if a.kemId != b.kemId {
		t.Errorf("incorrect kemId: got %d; want %d", a.kemId, b.kemId)
	}

	if !reflect.DeepEqual(a.suites, b.suites) {
		t.Errorf("incorrect suites: got %v; want %v", a.suites, b.suites)
	}

	if a.maxNameLen != b.maxNameLen {
		t.Errorf("incorrect maxNameLen: got %d; want %d", a.maxNameLen, b.maxNameLen)
	}

	if !bytes.Equal(a.ignoredExtensions, b.ignoredExtensions) {
		t.Errorf("incorrect ignoredExtensions: got %s; want %s", a.ignoredExtensions, b.ignoredExtensions)
	}
}
