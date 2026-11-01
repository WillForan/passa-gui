package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/adrg/xdg"
	"github.com/go-git/go-git/v6"
)

func ageenc(data string, publicKeys []string) (string, error) {
	recipients := make([]age.Recipient, 0, len(publicKeys))
	for _, publicKey := range publicKeys {
		recipient, err := age.ParseX25519Recipient(stripAgeComments(publicKey))
		if err != nil {
			return "", fmt.Errorf("parse public key %q: %w", publicKey, err)
		}
		recipients = append(recipients, recipient)
	}

	var out bytes.Buffer
	armored := armor.NewWriter(&out)
	encrypted, err := age.Encrypt(armored, recipients...)
	if err != nil {
		_ = armored.Close()
		return "", fmt.Errorf("create encrypted file: %w", err)
	}
	if _, err := encrypted.Write([]byte(data)); err != nil {
		_ = encrypted.Close()
		_ = armored.Close()
		return "", fmt.Errorf("encrypt data: %w", err)
	}
	if err := encrypted.Close(); err != nil {
		_ = armored.Close()
		return "", fmt.Errorf("finish encrypted file: %w", err)
	}
	if err := armored.Close(); err != nil {
		return "", fmt.Errorf("finish armored encrypted file: %w", err)
	}

	return out.String(), nil
}

func agedecrypt(privateKey, encryptedValue string) (string, error) {
	identity, err := age.ParseX25519Identity(stripAgeComments(privateKey))
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}

	reader := armor.NewReader(bytes.NewBufferString(encryptedValue))
	decrypted, err := age.Decrypt(reader, identity)
	if err != nil {
		return "", fmt.Errorf("decrypt value: %w", err)
	}

	plaintext, err := io.ReadAll(decrypted)
	if err != nil {
		return "", fmt.Errorf("read decrypted value: %w", err)
	}
	return string(plaintext), nil
}

// key file likley to have extra lines like '# public key: age...' and '# created: yyyy-...'
func stripAgeComments(value string) string {
	lines := strings.Split(value, "\n")
	for len(lines) > 0 && strings.HasPrefix(strings.TrimSpace(lines[0]), "#") {
		lines = lines[1:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func ageKeyComments(publicKey string) string {
	return fmt.Sprintf("# created: %s\n# public key: %s\n", time.Now().Format(time.RFC3339), publicKey)
}

func gitpull(name, remoteLoc string) {
	storeDir := path.Join(xdg.DataHome, "passa-gui", name)
	_, err := git.PlainClone(storeDir, &git.CloneOptions{
		URL:      remoteLoc,
		Progress: os.Stdout,
	})
	if err != nil {
		log.Printf("Failed to clone repository: %v", err)
	}
}

func keyStore() (string, error) {
	keyDir := os.Getenv("PASSA_STORE_KEYS")
	if keyDir == "" {
		keyDir = path.Join(xdg.DataHome, "passa-gui", ".keys")
	}
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return "", fmt.Errorf("create key store %q: %w", keyDir, err)
	}
	return keyDir, nil
}

func new_repo(repo_name string) (string, error) {
	// create a new password store by name
	storeDir := path.Join(xdg.DataHome, "passa-gui", repo_name)
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		return "", fmt.Errorf("create key store %q: %w", storeDir, err)
	}
	return storeDir, nil
}
func new_key(key_name string) (string, error) {
	keyDir, err := keyStore()
	if err != nil {
		return "", fmt.Errorf("create key store: %w", err)
	}
	if key_name == "" || key_name == "." || key_name == ".." || path.Base(key_name) != key_name {
		return "", fmt.Errorf("invalid key name %q", key_name)
	}

	privatePath := path.Join(keyDir, key_name)
	publicPath := privatePath + ".pub"
	for _, filePath := range []string{privatePath, publicPath} {
		if _, err := os.Stat(filePath); err == nil {
			return "", fmt.Errorf("key file %q already exists", filePath)
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("check key file %q: %w", filePath, err)
		}
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	publicKey := identity.Recipient().String()
	comments := ageKeyComments(publicKey)
	if err := os.WriteFile(privatePath, []byte(comments+identity.String()), 0o600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(publicPath, []byte(comments+publicKey), 0o644); err != nil {
		_ = os.Remove(privatePath)
		return "", fmt.Errorf("write public key: %w", err)
	}

	return privatePath, nil
}

func namecheck(name string) error {
	if name == "" || name == "." || name == ".." || path.Base(name) != name {
		return fmt.Errorf("invalid name %q", name)
	}
	return nil
}

// 3 places to find a public key:
// as a stand alone-file in (1) repo/.keys/name.pub or (2) keystore/name.pub
// or within the private key file (3) keystore/name in '# public key: age...'
func find_pubkey(keyName string, repo_dir string) (string, error) {
	// (1) check repo .keys file
	pubkey_file := path.Join(repo_dir, ".keys", keyName+".pub")
	if _, err := os.Stat(pubkey_file); repo_dir != "" && err == nil {
		pubKey, err := os.ReadFile(pubkey_file)
		if err != nil {
			return "", err
		}
		return string(pubKey), nil
	}

	// (2) check key store for pub
	keyDir, err := keyStore()
	if err != nil {
		return "", fmt.Errorf("access key store: %w", err)
	}
	pubkey_file = path.Join(keyDir, keyName+".pub")
	if _, err := os.Stat(pubkey_file); err == nil {
		pubKey, err := os.ReadFile(pubkey_file)
		if err != nil {
			return "", err
		}
		return string(pubKey), nil
	}

	// (3) read from private key
	privateKey, err := os.ReadFile(path.Join(keyDir, keyName))
	if err != nil {
		return "", fmt.Errorf("failed to find a public key for %s: %w", keyName, err)
	}
	for _, line := range strings.Split(string(privateKey), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# public key:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# public key:")), nil
		}
	}
	return "", fmt.Errorf("failed to find %q public key: private key has no public-key comment", keyName)
}

func new_secret(repo_dir string, key_names []string, secret_name string, secret string) (string, error) {
	if err := namecheck(secret_name); err != nil {
		return "", fmt.Errorf("invalid secret name %q: %w", secret_name, err)
	}
	if len(key_names) == 0 {
		return "", fmt.Errorf("at least one key is required")
	}

	publicKeys := make([]string, 0, len(key_names))
	for _, keyName := range key_names {
		if namecheck(keyName) != nil {
			return "", fmt.Errorf("invalid key name %q", keyName)
		}
		publicKey, err := find_pubkey(keyName, repo_dir)
		if err != nil {
			return "", fmt.Errorf("read public key %q: %w", keyName, err)
		}
		publicKeys = append(publicKeys, string(publicKey))
	}

	encrypted, err := ageenc(secret, publicKeys)
	if err != nil {
		return "", fmt.Errorf("encrypt secret: %w", err)
	}

	secretDir := path.Join(repo_dir, secret_name)
	if err := os.MkdirAll(secretDir, 0o700); err != nil {
		return "", fmt.Errorf("create secret directory: %w", err)
	}
	encPath := path.Join(secretDir, "enc")
	aclPath := path.Join(secretDir, "acl")
	for _, filePath := range []string{encPath, aclPath} {
		if _, err := os.Stat(filePath); err == nil {
			return "", fmt.Errorf("secret file %q already exists", filePath)
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("check secret file %q: %w", filePath, err)
		}
	}

	if err := os.WriteFile(encPath, []byte(encrypted), 0o600); err != nil {
		return "", fmt.Errorf("write encrypted secret: %w", err)
	}
	if err := os.WriteFile(aclPath, []byte(strings.Join(key_names, "\n")+"\n"), 0o600); err != nil {
		_ = os.Remove(encPath)
		return "", fmt.Errorf("write secret access list: %w", err)
	}

	return secretDir, nil
}

func updateSecret(secretDir string, keyNames []string, secret string) error {
	if len(keyNames) == 0 {
		return fmt.Errorf("at least one key is required")
	}

	publicKeys := make([]string, 0, len(keyNames))
	for _, keyName := range keyNames {
		if err := namecheck(keyName); err != nil {
			return err
		}
		publicKey, err := find_pubkey(keyName, "") // NOTE: no repo name avalable given
		if err != nil {
			return fmt.Errorf("read public key %q: %w", keyName, err)
		}
		publicKeys = append(publicKeys, string(publicKey))
	}

	encrypted, err := ageenc(secret, publicKeys)
	if err != nil {
		return fmt.Errorf("encrypt secret: %w", err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, "enc"), []byte(encrypted), 0o600); err != nil {
		return fmt.Errorf("write encrypted secret: %w", err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, "acl"), []byte(strings.Join(keyNames, "\n")+"\n"), 0o600); err != nil {
		return fmt.Errorf("write secret access list: %w", err)
	}
	return nil
}

// look at secret_dir/acl. find first also in keyStore
// use that to decrypt "enc"
func read_secret(secret_dir string) (string, error) {
	aclFile, err := os.Open(path.Join(secret_dir, "acl"))
	if err != nil {
		return "", fmt.Errorf("read access list: %w", err)
	}
	defer aclFile.Close()

	encrypted, err := os.ReadFile(path.Join(secret_dir, "enc"))
	if err != nil {
		return "", fmt.Errorf("read encrypted secret: %w", err)
	}

	scanner := bufio.NewScanner(aclFile)
	for scanner.Scan() {
		keyName := strings.TrimSpace(scanner.Text())
		if keyName == "" {
			continue
		}
		keyDir, keyErr := keyStore()
		if keyErr != nil {
			return "", fmt.Errorf("access key store: %w", keyErr)
		}
		privateKey, err := os.ReadFile(path.Join(keyDir, keyName))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("read private key %q: %w", keyName, err)
		}

		decrypted, err := agedecrypt(string(privateKey), string(encrypted))
		if err != nil {
			return "", fmt.Errorf("decrypt with key %q: %w", keyName, err)
		}
		return decrypted, nil
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read access list: %w", err)
	}

	return "", fmt.Errorf("no matching private key for secret %q", secret_dir)
}

// List all keys in xdg directory or PASSA_STORE_KEYS if set
func list_keys() ([]string, error) {
	keyDir, err := keyStore()
	if err != nil {
		return nil, fmt.Errorf("cannot list keys: %w", err)
	}
	entries, err := os.ReadDir(keyDir)
	if err != nil {
		return nil, fmt.Errorf("list keys in %q: %w", keyDir, err)
	}
	keys := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), ".pub") {
			continue
		}
		keys = append(keys, entry.Name())
	}
	return keys, nil
}

// list all secret directories in a repo/password store.
// returns all directories in repo_path with a 'enc' file
func list_secrets(repo_path string) ([]string, error) {
	secrets := make([]string, 0)
	err := filepath.WalkDir(repo_path, func(filePath string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() != "enc" {
			return nil
		}
		secrets = append(secrets, filepath.Dir(filePath))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list secrets in %q: %w", repo_path, err)
	}
	return secrets, nil
}

// list all secrets in a repo/password store
func list_repos() ([]string, error) {
	storeDir := path.Join(xdg.DataHome, "passa-gui")
	entries, err := os.ReadDir(storeDir)
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list repositories in %q: %w", storeDir, err)
	}

	repos := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == ".keys" {
			continue
		}
		repos = append(repos, path.Join(storeDir, entry.Name()))
	}
	return repos, nil
}

// find and read all acl files, counting each non-empty key name.
func repo_acls(repo_paths []string) (map[string]int, error) {
	counts := make(map[string]int)
	for _, repoPath := range repo_paths {
		err := filepath.WalkDir(repoPath, func(filePath string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || entry.Name() != "acl" {
				return nil
			}

			aclFile, err := os.Open(filePath)
			if err != nil {
				return fmt.Errorf("open ACL file %q: %w", filePath, err)
			}
			defer aclFile.Close()

			scanner := bufio.NewScanner(aclFile)
			for scanner.Scan() {
				keyName := strings.TrimSpace(scanner.Text())
				if keyName != "" {
					counts[keyName]++
				}
			}
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("read ACL file %q: %w", filePath, err)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("scan repository %q: %w", repoPath, err)
		}
	}
	return counts, nil
}
