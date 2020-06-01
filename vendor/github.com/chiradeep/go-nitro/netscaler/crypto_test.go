/*
Copyright 2016 Citrix Systems, Inc

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
	"crypto/sha256"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	t.Log("Test encryption decryption using AES GCM")

	ks := NewKeyspec([]byte("masterkey"), 8, 1000, 32, sha256.New)
	plaintext := "This is very sensistive information"
	ciphertext := ks.encrypt(plaintext)

	if plaintext != ks.decrypt(ciphertext) {
		t.Error("Error! Expected to match decrypted text with input text")
	} else {
		t.Log("Success: Decryption provided correct plain text")
	}

	alteredCipher := ciphertext + ciphertext
	if ks.decrypt(alteredCipher) != "" {
		t.Error("Error! Decryption should have returned empty string.")
	} else {
		t.Log("Success: Decrypting tampered cipher text doesn't give anything")
	}

	ks.Masterkey = []byte("Masterkey")
	if plaintext == ks.decrypt(ciphertext) {
		t.Error("Error! Cipher should not have been decrypted.")
	} else {
		t.Log("Success: Decryption with different Master key doesn't work.")
	}

}
