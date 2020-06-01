/*
Copyright 2016 Citrix Systems, Inc, All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package netscaler

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"hash"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// Keyspec structure has PBKDF2 key specification details such as key length, salt size and iterations
type Keyspec struct {
	Masterkey  []byte
	SaltSize   int
	Iterations int
	KeyLen     int
	Digest     func() hash.Hash
}

// NewKeyspec creates PBKDF2 Key specification used for encrypting password in go-nitro
func NewKeyspec(masterkey []byte, saltSize, iter, keyLen int, digest func() hash.Hash) *Keyspec {
	return &Keyspec{
		Masterkey:  masterkey,
		SaltSize:   saltSize,
		Iterations: iter,
		KeyLen:     keyLen,
		Digest:     digest,
	}
}

func (ks *Keyspec) deriveKey(salt []byte) ([]byte, []byte) {
	if salt == nil {
		salt = make([]byte, ks.SaltSize)
		// http://www.ietf.org/rfc/rfc2898.txt
		// Salt.
		rand.Read(salt)
	}
	return pbkdf2.Key(ks.Masterkey, salt, ks.Iterations, ks.KeyLen, ks.Digest), salt
}

func (ks *Keyspec) encrypt(plaintext string) string {
	key, salt := ks.deriveKey(nil)
	iv := make([]byte, 12)
	// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	// Section 8.2
	rand.Read(iv)
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	data := aesgcm.Seal(nil, iv, []byte(plaintext), nil)
	return hex.EncodeToString(salt) + "-" + hex.EncodeToString(iv) + "-" + hex.EncodeToString(data)
}

func (ks *Keyspec) decrypt(ciphertext string) string {
	arr := strings.Split(ciphertext, "-")
	salt, _ := hex.DecodeString(arr[0])
	iv, _ := hex.DecodeString(arr[1])
	data, _ := hex.DecodeString(arr[2])
	key, _ := ks.deriveKey(salt)
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	data, _ = aesgcm.Open(nil, iv, data, nil)
	return string(data)
}
