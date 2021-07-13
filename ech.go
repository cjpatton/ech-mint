// Package ech implements the minting logic for the "Encrypted ClientHello
// (ECH)" extension for TLS. It is compatible with draft-ietf-tls-esni-08.
package ech

import (
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"

	"golang.org/x/crypto/cryptobyte"
)

const (
	// Supported ECH versions
	VersionECHDraft12 uint16 = 0xfe0c
)

// ECHConfig represents an ECH configuration.
type ECHConfig struct {
	pk  kem.PublicKey
	raw []byte

	// Parsed from raw
	version           uint16
	configId          uint8
	rawPublicName     []byte
	rawPublicKey      []byte
	kemId             uint16
	suites            []hpkeSymmetricCipherSuite
	maxNameLen        uint8
	ignoredExtensions []byte
}

type hpkeSymmetricCipherSuite struct {
	kdfId, aeadId uint16
}

// UnmarshalECHConfigs parses a sequence of ECH configurations, skipping
// configurations with unrecognized versions.
func UnmarshalECHConfigs(raw []byte) ([]ECHConfig, error) {
	var (
		err         error
		config      ECHConfig
		t, contents cryptobyte.String
	)
	configs := make([]ECHConfig, 0)
	s := cryptobyte.String(raw)
	if !s.ReadUint16LengthPrefixed(&t) || !s.Empty() {
		return configs, errors.New("error parsing configs")
	}
	raw = raw[2:]
ConfigsLoop:
	for !t.Empty() {
		l := len(t)
		if !t.ReadUint16(&config.version) ||
			!t.ReadUint16LengthPrefixed(&contents) {
			return nil, errors.New("error parsing config")
		}
		n := l - len(t)
		config.raw = raw[:n]
		raw = raw[n:]

		if config.version != VersionECHDraft12 {
			continue ConfigsLoop
		}
		if !readConfigContents(&contents, &config) {
			return nil, errors.New("error parsing config contents")
		}

		kem := hpke.KEM(config.kemId)
		if !kem.IsValid() {
			continue ConfigsLoop
		}
		config.pk, err = kem.Scheme().UnmarshalBinaryPublicKey(config.rawPublicKey)
		if err != nil {
			return nil, fmt.Errorf("error parsing public key: %s", err)
		}
		configs = append(configs, config)
	}
	return configs, nil
}

func MarshalECHConfigs(configs []ECHConfig) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, config := range configs {
			if config.raw != nil {
				b.AddBytes(config.raw)
			} else {
				addConfig(b, config)
			}
		}
	})
	return b.Bytes()
}

func addConfig(b *cryptobyte.Builder, config ECHConfig) {
	b.AddUint16(config.version)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(config.configId)
		b.AddUint16(config.kemId)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(config.rawPublicKey)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, suite := range config.suites {
				b.AddUint16(suite.kdfId)
				b.AddUint16(suite.aeadId)
			}
		})
		b.AddUint8(config.maxNameLen)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(config.rawPublicName)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(config.ignoredExtensions)
		})
	})
}

func readConfigContents(contents *cryptobyte.String, config *ECHConfig) bool {
	var t cryptobyte.String
	if !contents.ReadUint8(&config.configId) ||
		!contents.ReadUint16(&config.kemId) ||
		!contents.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&config.rawPublicKey, len(t)) ||
		!contents.ReadUint16LengthPrefixed(&t) ||
		len(t)%4 != 0 {
		return false
	}

	config.suites = nil
	for !t.Empty() {
		var kdfId, aeadId uint16
		if !t.ReadUint16(&kdfId) || !t.ReadUint16(&aeadId) {
			// This indicates an internal bug.
			panic("internal error while parsing contents.cipher_suites")
		}
		config.suites = append(config.suites, hpkeSymmetricCipherSuite{kdfId, aeadId})
	}

	if !contents.ReadUint8(&config.maxNameLen) ||
		!contents.ReadUint8LengthPrefixed(&t) ||
		!t.ReadBytes(&config.rawPublicName, len(t)) ||
		!contents.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&config.ignoredExtensions, len(t)) ||
		!contents.Empty() {
		return false
	}
	return true
}

// ECHKey represents an ECH key and its corresponding configuration.
// The encoding of an ECH Key has the format defined below (in TLS syntax). Note
// that the ECH standard does not specify this format.
//
// struct {
//     opaque sk<0..2^16-1>;
//     ECHConfig config<0..2^16>; // draft-ietf-tls-esni-11
// } ECHKey;
type ECHKey struct {
	sk kem.PrivateKey

	// Parsed from raw
	rawSecretKey []byte
	Config       ECHConfig
}

// UnmarshalECHKeys parses a sequence of ECH keys.
func UnmarshalECHKeys(raw []byte) ([]ECHKey, error) {
	var (
		err                  error
		key                  ECHKey
		sk, config, contents cryptobyte.String
	)
	s := cryptobyte.String(raw)
	keys := make([]ECHKey, 0)
KeysLoop:
	for !s.Empty() {
		if !s.ReadUint16LengthPrefixed(&sk) ||
			!s.ReadUint16LengthPrefixed(&config) {
			return nil, errors.New("error parsing key")
		}

		key.Config.raw = config
		if !config.ReadUint16(&key.Config.version) ||
			!config.ReadUint16LengthPrefixed(&contents) ||
			!config.Empty() {
			return nil, errors.New("error parsing config")
		}

		if key.Config.version != VersionECHDraft12 {
			continue KeysLoop
		}
		if !readConfigContents(&contents, &key.Config) {
			return nil, errors.New("error parsing config contents")
		}

		for _, suite := range key.Config.suites {
			if !hpke.KDF(suite.kdfId).IsValid() ||
				!hpke.AEAD(suite.aeadId).IsValid() {
				continue KeysLoop
			}
		}

		kem := hpke.KEM(key.Config.kemId)
		if !kem.IsValid() {
			continue KeysLoop
		}
		key.Config.pk, err = kem.Scheme().UnmarshalBinaryPublicKey(key.Config.rawPublicKey)
		if err != nil {
			return nil, fmt.Errorf("error parsing public key: %s", err)
		}
		key.rawSecretKey = sk
		key.sk, err = kem.Scheme().UnmarshalBinaryPrivateKey(sk)
		if err != nil {
			return nil, fmt.Errorf("error parsing secret key: %s", err)
		}

		keys = append(keys, key)
	}
	return keys, nil
}

// XXX
func MarshalECHKeys(keys []ECHKey) ([]byte, error) {
	var b cryptobyte.Builder
	for _, key := range keys {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(key.rawSecretKey)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			addConfig(b, key.Config)
		})
	}
	return b.Bytes()
}

type ECHConfigTemplate struct {
	// The version of ECH to use for this configuration.
	Version uint16

	// Id is the unique identifier for this configuration.
	Id uint8

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
	MaximumNameLength uint8

	// Extensions to add to the end of the configuration. This implementation
	// currently doesn't handle extensions, but this field is useful for testing
	// purposes.
	ignoredExtensions []byte
}

// DefaultConfigTemplate returns an ECHConfigTemplate with suitable defaults.
func DefaultConfigTemplate(id uint8) ECHConfigTemplate {
	return ECHConfigTemplate{
		Version:    VersionECHDraft12,
		Id:         id,
		PublicName: "cloudflare-esni.com",
		KemId:      uint16(hpke.KEM_X25519_HKDF_SHA256),
		KdfIds:     []uint16{uint16(hpke.KDF_HKDF_SHA256)},
		AeadIds:    []uint16{uint16(hpke.AEAD_AES128GCM)},
		// Use the default padding scheme.
		MaximumNameLength: 0,
	}
}

// the parameters specified by `template`.
func GenerateKey(template ECHConfigTemplate, rand io.Reader) (*ECHKey, error) {
	pk, sk, err := hpke.KEM(template.KemId).Scheme().GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	rawPublicKey, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}

	rawSecretKey, err := sk.MarshalBinary()
	if err != nil {
		return nil, err
	}

	suites := make([]hpkeSymmetricCipherSuite, 0, len(template.KdfIds)*len(template.AeadIds))
	for _, kdfId := range template.KdfIds {
		for _, aeadId := range template.AeadIds {
			suites = append(suites, hpkeSymmetricCipherSuite{kdfId, aeadId})
		}
	}

	return &ECHKey{
		sk:           sk,
		rawSecretKey: rawSecretKey,
		Config: ECHConfig{
			pk:                pk,
			raw:               nil,
			version:           template.Version,
			configId:          template.Id,
			rawPublicName:     []byte(template.PublicName),
			rawPublicKey:      rawPublicKey,
			kemId:             template.KemId,
			suites:            suites,
			maxNameLen:        template.MaximumNameLength,
			ignoredExtensions: template.ignoredExtensions,
		},
	}, nil
}
