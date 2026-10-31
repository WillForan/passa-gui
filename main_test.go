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

func TestNewKeyWritesPrivateAndPublicKeys(t *testing.T) {
	keyDir := filepath.Join(t.TempDir(), "keys")
	t.Setenv("PASSA_STORE_KEYS", keyDir)

	privatePath, err := new_key("test-key")
	if err != nil {
		t.Fatal(err)
	}
	if privatePath != filepath.Join(keyDir, "test-key") {
		t.Fatalf("new_key() path = %q", privatePath)
	}

	privateData, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	publicData, err := os.ReadFile(privatePath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	privateKey := string(privateData)
	publicKey := string(publicData)
	if _, err := age.ParseX25519Identity(privateKey); err != nil {
		t.Fatalf("private key is invalid: %v", err)
	}
	if _, err := age.ParseX25519Recipient(publicKey); err != nil {
		t.Fatalf("public key is invalid: %v", err)
	}

	if _, err := new_key("test-key"); err == nil {
		t.Fatal("new_key() succeeded for an existing key")
	}
}

func TestNewSecretWritesEncryptedSecretAndACL(t *testing.T) {
	keyDir := filepath.Join(t.TempDir(), "keys")
	repoDir := filepath.Join(t.TempDir(), "repo")
	t.Setenv("PASSA_STORE_KEYS", keyDir)

	privatePath, err := new_key("test-key")
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}

	secretDir, err := new_secret(repoDir, []string{"test-key"}, "example", "secret value")
	if err != nil {
		t.Fatal(err)
	}
	if secretDir != filepath.Join(repoDir, "example") {
		t.Fatalf("new_secret() path = %q", secretDir)
	}

	encrypted, err := os.ReadFile(filepath.Join(secretDir, "enc"))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := agedecrypt(string(privateKey), string(encrypted))
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != "secret value" {
		t.Fatalf("decrypted secret = %q, want %q", decrypted, "secret value")
	}

	acl, err := os.ReadFile(filepath.Join(secretDir, "acl"))
	if err != nil {
		t.Fatal(err)
	}
	if string(acl) != "test-key\n" {
		t.Fatalf("ACL = %q, want %q", acl, "test-key\n")
	}

	got, err := read_secret(secretDir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "secret value" {
		t.Fatalf("read_secret() = %q, want %q", got, "secret value")
	}
}
