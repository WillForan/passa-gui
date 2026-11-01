package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/adrg/xdg"
)

func TestListSecretsFindsEncryptedSecretDirectories(t *testing.T) {
	repoDir := t.TempDir()
	secretDirs := []string{
		filepath.Join(repoDir, "personal", "email"),
		filepath.Join(repoDir, "work", "cloud"),
	}
	for _, secretDir := range secretDirs {
		if err := os.MkdirAll(secretDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(secretDir, "enc"), []byte("encrypted"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(repoDir, "not-a-secret"), []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := list_secrets(repoDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(secretDirs) {
		t.Fatalf("list_secrets() = %v, want %v", got, secretDirs)
	}
	for i := range secretDirs {
		if got[i] != secretDirs[i] {
			t.Fatalf("list_secrets() = %v, want %v", got, secretDirs)
		}
	}
}

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

func TestGenerateTOTP(t *testing.T) {
	for _, secret := range []string{
		"JBSWY3DPEHPK3PXP",
		"otpauth://totp/example?secret=JBSWY3DPEHPK3PXP",
	} {
		code, err := generateTOTP(secret)
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != 6 {
			t.Fatalf("generateTOTP(%q) = %q, want six digits", secret, code)
		}
		for _, character := range code {
			if character < '0' || character > '9' {
				t.Fatalf("generateTOTP(%q) = %q, want digits", secret, code)
			}
		}
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
	if !strings.HasPrefix(privateKey, "# created: ") || !strings.Contains(privateKey, "# public key: ") {
		t.Fatalf("private key is missing age metadata comments: %q", privateKey)
	}
	if _, err := age.ParseX25519Identity(stripAgeComments(privateKey)); err != nil {
		t.Fatalf("private key is invalid: %v", err)
	}
	if _, err := age.ParseX25519Recipient(stripAgeComments(publicKey)); err != nil {
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

func TestListReposReturnsRepositoryDirectories(t *testing.T) {
	dataHome := t.TempDir()
	originalDataHome := xdg.DataHome
	xdg.DataHome = dataHome
	t.Cleanup(func() {
		xdg.DataHome = originalDataHome
	})

	storeDir := filepath.Join(dataHome, "passa-gui")
	if err := os.MkdirAll(filepath.Join(storeDir, "repo-a"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(storeDir, "repo-b"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(storeDir, ".keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(storeDir, "not-a-repo"), []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}

	repos, err := list_repos()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(storeDir, "repo-a"),
		filepath.Join(storeDir, "repo-b"),
	}
	if len(repos) != len(want) {
		t.Fatalf("list_repos() = %v, want %v", repos, want)
	}
	for i := range want {
		if repos[i] != want[i] {
			t.Fatalf("list_repos() = %v, want %v", repos, want)
		}
	}

}

func TestRepoACLsCountsKeysRecursively(t *testing.T) {
	repoA := t.TempDir()
	repoB := t.TempDir()
	for _, file := range []struct {
		root string
		path string
		data string
	}{
		{repoA, filepath.Join("one", "acl"), "alpha\nbeta\nalpha\n"},
		{repoA, filepath.Join("two", "nested", "acl"), "beta\n\n"},
		{repoB, filepath.Join("acl"), "gamma\nalpha\n"},
	} {
		filePath := filepath.Join(file.root, file.path)
		if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filePath, []byte(file.data), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := repo_acls([]string{repoA, repoB})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"alpha": 3, "beta": 2, "gamma": 1}
	if len(got) != len(want) {
		t.Fatalf("repo_acls() = %v, want %v", got, want)
	}
	for key, count := range want {
		if got[key] != count {
			t.Fatalf("repo_acls() = %v, want %v", got, want)
		}
	}

}
