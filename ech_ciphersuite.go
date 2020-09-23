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

package ech

import (
	"fmt"
)

// CipherSuite represents an ECH ciphersuite, a KDF/AEAD algorithm pair.  This
// is different from an HPKE ciphersuite, which represents a KEM, KDF, and an
// AEAD algorithm.
type CipherSuite struct {
	KdfId, AeadId uint16
}

// IsSupported returns true if the caller supports the KEM and at least one ECH
// ciphersuite indicated by this configuration.
func (config *Config) IsSupported() bool {
	_, err := config.NegotiateCipherSuite()
	if err != nil || !isKemSupported(config.contents.KemId) {
		return false
	}
	return true
}

// IsPeerCipherSuiteSupported returns true if this configuration indicates
// support for the given ciphersuite.
func (config *Config) IsPeerCipherSuiteSupported(suite CipherSuite) bool {
	for _, configSuite := range config.CipherSuites() {
		if suite == configSuite {
			return true
		}
	}
	return false
}

// NegotiateCipherSuite returns the first ciphersuite indicated by this
// configuration that is supported by the caller.
func (config *Config) NegotiateCipherSuite() (CipherSuite, error) {
	for i, _ := range config.contents.CipherSuites {
		if isCipherSuiteSupported(config.contents.CipherSuites[i]) {
			return config.contents.CipherSuites[i], nil
		}
	}
	return CipherSuite{}, fmt.Errorf("could not negotiate a ciphersuite")
}

func isCipherSuiteSupported(suite CipherSuite) bool {
	// NOTE: Stand-in values for KEM algorithm is ignored.
	_, err := AssembleHpkeCipherSuite(dummyKemId, suite.KdfId, suite.AeadId)
	return err == nil
}

func isKemSupported(kemId uint16) bool {
	// NOTE: Stand-in values for KDF/AEAD algorithms are ignored.
	_, err := AssembleHpkeCipherSuite(kemId, dummyKdfId, dummyAeadId)
	return err == nil
}
