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
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestKeySerialization(t *testing.T) {
	template := DefaultConfigTemplate()
	template.ignoredExtensions = []byte("raw ECHConfigContents.extensions")
	want, err := GenerateKey(template, rand.Reader, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	rawKey, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	got, err := UnmarshalKey(rawKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got.sk.marshaled(), want.sk.marshaled()) {
		t.Errorf("sk: got %x; want %x", got.sk, want.sk)
	}

	if got.Created != want.Created {
		t.Errorf("Created: got %s; want %s", got.Created, want.Created)
	}

	if got.Config.Version != want.Config.Version {
		t.Errorf("Config.Version: got %x; want %x", got.Config.Version, want.Config.Version)
	}

	if !bytes.Equal(got.Config.Contents, want.Config.Contents) {
		t.Errorf("Config.Contents: got %v; want %v", got.Config.Contents, want.Config.Contents)
	}

	if got.Config.contents.KemId != want.Config.contents.KemId {
		t.Errorf("Config.contents.kemId: got %x; want %x", got.Config.contents.KemId, want.Config.contents.KemId)
	}

	bad := false
	if len(got.Config.contents.CipherSuites) != len(want.Config.contents.CipherSuites) {
		bad = true
	} else {
		for i, _ := range got.Config.contents.CipherSuites {
			if got.Config.contents.CipherSuites[i] != want.Config.contents.CipherSuites[i] {
				bad = true
			}
		}
	}
	if bad {
		t.Errorf("Config.contents.CipherSuites: got %v; want %v", got.Config.contents.CipherSuites, want.Config.contents.CipherSuites)
	}

	if got.Config.contents.MaximumNameLength != want.Config.contents.MaximumNameLength {
		t.Errorf("Config.contents.MaximumNameLength: got %d; want %d", got.Config.contents.MaximumNameLength, want.Config.contents.MaximumNameLength)
	}

	if !bytes.Equal(got.Config.contents.IgnoredExtensions, want.Config.contents.IgnoredExtensions) {
		t.Errorf("Config.contents.IgnoredExtensions: got %v; want %v", got.Config.contents.IgnoredExtensions, want.Config.contents.IgnoredExtensions)
	}
}
