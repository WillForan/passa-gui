package main

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func TestAgeencEncryptsForAllRecipients(t *testing.T) {
	firstIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	secondIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	const plaintext = "secret value"
	encrypted, err := ageenc(plaintext, []string{
		firstIdentity.Recipient().String(),
		secondIdentity.Recipient().String(),
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, testCase := range []struct {
		name       string
		identity   age.Identity
		privateKey string
	}{
		{name: "first recipient", identity: firstIdentity, privateKey: firstIdentity.String()},
		{name: "second recipient", identity: secondIdentity, privateKey: secondIdentity.String()},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := agedecrypt(testCase.privateKey, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if got != plaintext {
				t.Fatalf("decrypted plaintext = %q, want %q", got, plaintext)
			}
		})
	}
}

func TestKeyStoreUsesConfiguredDirectory(t *testing.T) {
	keyDir := filepath.Join(t.TempDir(), "keys", "nested")
	t.Setenv("PASSA_STORE_KEYS", keyDir)

	got, err := keyStore()
	if err != nil {
		t.Fatal(err)
	}
	if got != keyDir {
		t.Fatalf("keyStore() = %q, want %q", got, keyDir)
	}

	info, err := os.Stat(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("keyStore path %q is not a directory", keyDir)
	}

	// imdepotent -- run again and pickup already created dir
	got, err = keyStore()
	if got != keyDir {
		t.Fatalf("keyStore() = %q, want %q", got, keyDir)
	}
}
