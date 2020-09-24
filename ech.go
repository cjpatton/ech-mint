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

// Package ech implements the minting logic for the "Encrypted ClientHello
// (ECH)" extension for TLS. It is compatible with draft-ietf-tls-esni-08.
package ech

import (
	"fmt"
	"io"

	"github.com/cisco/go-hpke"
	"github.com/cisco/go-tls-syntax"

	"golang.org/x/crypto/cryptobyte"
)

const (
	// Supported ECH versions
	VersionECHDraft08 uint16 = 0xff08
)

// ConfigTemplate defines the parameters for generating an ECH configuration and
// corresponding secret key.
type ConfigTemplate struct {
	// The version of ECH to use for this configuration.
	Version uint16

	// The name of the client-facing server.
	PublicName string

	// The algorithm used for the KEM key pair. Available algorithms are
	// enumerated in this package.
	KemId uint16

	// The KDF algorithms the server for this configuration.
	KdfIds []uint16

	// The AEAD algorithms the server offers for this configuration.
	AeadIds []uint16

	// The maximum length of any server name in the anonymity set. In the ECH
	// extension, the ClientHelloInner is padded to this length in order to
	// protect the server name. This value may be 0, in which case the default
	// padding is used.
	MaximumNameLength uint16

	// Extensions to add to the end of the configuration. This implementation
	// currently doesn't handle extensions, but this field is useful for testing
	// purposes.
	ignoredExtensions []byte
}

// DefaultConfigTemplate returns an ECHConfigTemplate with suitable defaults.
func DefaultConfigTemplate() ConfigTemplate {
	return ConfigTemplate{
		Version:    VersionECHDraft08,
		PublicName: "cloudflare-esni.com",
		KemId:      HPKE_KEM_DHKEM_X25519_HKDF_SHA256,
		// NOTE: We offer two different KDFs by default so that our prototype
		// can exercise the logic of computing the configuration identifier
		// using the client's selected ciphersuite.
		KdfIds:  []uint16{HPKE_KDF_HKDF_SHA256, HPKE_KDF_HKDF_SHA384},
		AeadIds: []uint16{HPKE_AEAD_AES128_GCM, HPKE_AEAD_CHACHA20_POLY1305},
		// Use the default padding scheme.
		MaximumNameLength: 0,
	}
}

// Config represents an ECH configuration.
type Config struct {
	// Operational parameters
	contents serialConfigContents
	pk       hpkePublicKey

	// The ECH version for which this configuration is used.
	Version uint16

	// The length of the ECHConfigContents.
	Length uint16

	// The opaque ECHConfigContents.
	Contents []byte
}

// UnmarshalECHConfigs parses a sequence of ECH configurations.
func UnmarshalConfigs(raw []byte) ([]Config, error) {
	configs := make([]Config, 0)
	var config Config
	for len(raw) > 0 {
		n, err := readConfig(raw, &config)
		if err != nil {
			return nil, err
		}
		raw = raw[n:]
		configs = append(configs, config)
	}
	return configs, nil
}

// UnmarshalConfig parses an ECH configuration.
func UnmarshalConfig(raw []byte) (*Config, error) {
	config := new(Config)
	if n, err := readConfig(raw, config); err != nil {
		return nil, err
	} else if n != len(raw) {
		return nil, fmt.Errorf("structure too long")
	}
	return config, nil
}

// readConfig consumes the next ECHConfig encoded by `raw` and returns its
// length.
func readConfig(raw []byte, config *Config) (int, error) {
	// Parse the version and ensure we know how to proceed before attempting to
	// parse the configuration contents. Currently on draft-ietf-tls-esni-08 is
	// supported.
	s := cryptobyte.String(raw)
	if !s.ReadUint16(&config.Version) {
		return 0, fmt.Errorf("error parsing version")
	}

	if config.Version != VersionECHDraft08 {
		return 0, fmt.Errorf("version not supported")
	}

	// Set the length of the opaque contents.
	if !s.ReadUint16(&config.Length) {
		return 0, fmt.Errorf("error parsing length")
	}

	// Parse the configuration contents.
	n, err := syntax.Unmarshal(s, &config.contents)
	if err != nil {
		return 0, err
	}

	if uint16(n) != config.Length {
		return 0, fmt.Errorf("contents length: got %d; expected %d", n, config.Length)
	}

	// Set the opaque contents.
	config.Contents = raw[4 : n+4]

	// Parse the HPKE public key.
	pk, err := unmarshalHpkePublicKey(config.contents.PublicKey, config.contents.KemId)
	if err != nil {
		return 0, fmt.Errorf("error parsing HPKE public key: %s", err)
	}
	config.pk = *pk

	return n + 4, nil
}

// Marshal returns the serialized ECH configuration.
func (config *Config) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16(config.Version)
	b.AddUint16(config.Length)
	b.AddBytes(config.Contents)
	return b.Bytes()
}

// PublicName returns the name of the client-facing server.
func (config *Config) PublicName() string {
	return string(config.contents.PublicName)
}

// Kem returns the KEM public key.
func (config *Config) Kem() hpke.KEMPublicKey {
	return config.pk.kemPk
}

// KemId returns the identity of the KEM algorithm.
func (config *Config) KemId() uint16 {
	return config.contents.KemId
}

// CipherSuites returns the ECH ciphersuites offered by the server for this
// configuration.
func (config *Config) CipherSuites() []CipherSuite {
	return config.contents.CipherSuites
}

// Key represents an ECH key and its corresponding configuration.
type Key struct {
	// Operational parameters
	sk hpkeSecretKey

	// The configuration corresponding to this key.
	Config *Config
}

// GenerateKey generates a new ECH key and corresponding configuration using
// the parameters specified by `template`.
func GenerateKey(template ConfigTemplate, rand io.Reader) (*Key, error) {
	// Ensure the KEM algorithm is supported and generate an HPKE key pair.
	pk, sk, err := generateHpkeKeyPair(rand, template.KemId)
	if err != nil {
		return nil, err // May indicate the KEM algorithm is not supported.
	}

	// Ensure the configuration names at least one ciphersuite.
	if len(template.KdfIds) == 0 || len(template.AeadIds) == 0 {
		return nil, fmt.Errorf("config does not name a ciphersuite")
	}

	// Compute the list of ciphersuites.
	suites := make([]CipherSuite, 0)
	for _, kdfId := range template.KdfIds {
		for _, aeadId := range template.AeadIds {
			suites = append(suites, CipherSuite{kdfId, aeadId})
		}
	}

	contents := serialConfigContents{
		PublicName:        []byte(template.PublicName),
		PublicKey:         pk.marshaled(),
		KemId:             template.KemId,
		CipherSuites:      suites,
		MaximumNameLength: template.MaximumNameLength,
		IgnoredExtensions: nil,
	}

	rawContents, err := syntax.Marshal(contents)
	if err != nil {
		return nil, err
	}

	config := &Config{
		pk:       *pk,
		contents: contents,
		Version:  template.Version,
		Length:   uint16(len(rawContents)),
		Contents: rawContents,
	}
	return &Key{*sk, config}, nil
}

// UnmarshalKeys parses a sequence of ECH keys.
func UnmarshalKeys(raw []byte) ([]Key, error) {
	keys := make([]Key, 0)
	var key Key
	for len(raw) > 0 {
		n, err := readKey(raw, &key)
		if err != nil {
			return nil, err
		}
		raw = raw[n:]
		keys = append(keys, key)
	}
	return keys, nil
}

// UnmarshalKey parses an ECH key.
func UnmarshalKey(raw []byte) (*Key, error) {
	key := new(Key)
	if n, err := readKey(raw, key); err != nil {
		return nil, err
	} else if n != len(raw) {
		return nil, fmt.Errorf("structure too long")
	}
	return key, nil
}

// Marshal serializes an ECH key.
func (key *Key) Marshal() ([]byte, error) {
	var ser serialKey
	var err error
	ser.Key = key.sk.marshaled()
	ser.Config, err = key.Config.Marshal()
	if err != nil {
		return nil, err
	}
	return syntax.Marshal(ser)
}

// Kem returns the KEM secret key.
func (key *Key) Kem() hpke.KEMPrivateKey {
	return key.sk.kemSk
}

func readKey(raw []byte, key *Key) (int, error) {
	var ser serialKey
	n, err := syntax.Unmarshal(raw, &ser)
	if err != nil {
		return 0, err
	}

	key.Config, err = UnmarshalConfig(ser.Config)
	if err != nil {
		return 0, err
	}

	sk, err := unmarshalHpkeSecretKey(ser.Key, key.Config.contents.KemId)
	if err != nil {
		return 0, nil
	}
	key.sk = *sk
	return n, nil
}

// serialConfigContents represents an ECHConfigContents structure as defined in
// draft-ietf-tls-esni-08.
type serialConfigContents struct {
	PublicName        []byte `tls:"head=2"`
	PublicKey         []byte `tls:"head=2"`
	KemId             uint16
	CipherSuites      []CipherSuite `tls:"head=2,min=4,max=65532"` //4..2^16-4
	MaximumNameLength uint16

	// In draft-ietf-tls-esni-08, the last field of the ECHConfig is
	// `extensions`. This implementation currently ignores it.
	IgnoredExtensions []byte `tls:"head=2"`
}

// serialKey represents a serializeable Key object.
type serialKey struct {
	Key    []byte `tls:"head=2"`
	Config []byte `tls:"head=2"`
}
