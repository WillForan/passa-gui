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

	"filippo.io/age"
	"filippo.io/age/armor"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/adrg/xdg"
	"github.com/go-git/go-git/v6"
)

/*
 expect
  * git manged repository per password store (may have multiple?)
  * seperate private key store (what if key names are shared but different kyes across stores?)
  * public keys for encoding
 want easy/friendly graphical inteface to
  * decode (age with private key)
  * totp for matching strings or 'totp' name
  * update (managed with git push)

passa structure is folder per secret.
  secret_name/
  |-- readme.* # public notes about the secret
  |-- acl      # key names (recipients that can decode). 1 per line
  `-- enc      # age PEM encoded secret

dec like:
   cat $enc | age -d -i $PASSA_STORE_KEYS/${usable_keys[0]}

enc like:
  age -e -a "${pubkeys[@]}" > $encdir/enc
  printf "%s\n" "${acls[@]}" > $encdir/acl
*/

func main() {
	a := app.New()
	w := a.NewWindow("Passa")
	w.Resize(fyne.NewSize(1100, 700))

	repos, err := list_repos()
	if err != nil {
		repos = []string{}
	}
	repoList := widget.NewList(
		func() int { return len(repos) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, object fyne.CanvasObject) {
			object.(*widget.Label).SetText(filepath.Base(repos[id]))
		},
	)

	secrets := []string{}
	secretList := widget.NewList(
		func() int { return len(secrets) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, object fyne.CanvasObject) {
			object.(*widget.Label).SetText(secretListText(secrets[id]))
		},
	)
	secretDisplay := widget.NewLabel("")
	secretDisplay.Wrapping = fyne.TextWrapWord

	refreshRepos := func() {
		updated, err := list_repos()
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		repos = updated
		repoList.Refresh()
	}
	refreshSecrets := func(repoPath string) {
		updated, err := list_secrets(repoPath)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		secrets = updated
		secretList.Refresh()
		secretDisplay.SetText("")
	}

	repoList.OnSelected = func(id widget.ListItemID) {
		if id < len(repos) {
			refreshSecrets(repos[id])
		}
	}
	secretList.OnSelected = func(id widget.ListItemID) {
		if id >= len(secrets) {
			return
		}
		secret, err := read_secret(secrets[id])
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		secretDisplay.SetText(secret)
	}

	addButton := widget.NewButton("Add", nil)
	addButton.OnTapped = func() {
		menu := fyne.NewMenu("",
			fyne.NewMenuItem("Store from directory", func() {
				dialog.ShowInformation("Not implemented", "Storing an existing directory is not implemented yet.", w)
			}),
			fyne.NewMenuItem("Import by clone", func() {
				dialog.ShowInformation("Not implemented", "Importing a repository by clone is not implemented yet.", w)
			}),
			fyne.NewMenuItem("New", func() {
				dialog.ShowEntryDialog("New repository", "Repository name", func(name string) {
					if _, err := new_repo(strings.TrimSpace(name)); err != nil {
						dialog.ShowError(err, w)
						return
					}
					refreshRepos()
				}, w)
			}),
		)
		widget.ShowPopUpMenuAtRelativePosition(menu, w.Canvas(), fyne.NewPos(0, addButton.Size().Height), addButton)
	}

	leftPane := container.NewBorder(nil, addButton, nil, nil, repoList)
	middlePane := container.NewBorder(nil, nil, nil, nil, secretList)
	rightPane := container.NewScroll(secretDisplay)
	leftMiddle := container.NewHSplit(leftPane, middlePane)
	leftMiddle.Offset = 0.3
	mainSplit := container.NewHSplit(leftMiddle, rightPane)
	mainSplit.Offset = 0.5
	w.SetContent(mainSplit)

	w.ShowAndRun()
}

func secretListText(secretPath string) string {
	acl, err := os.ReadFile(filepath.Join(secretPath, "acl"))
	if err != nil {
		return filepath.Base(secretPath)
	}
	keys := strings.Fields(string(acl))
	if len(keys) == 0 {
		return filepath.Base(secretPath)
	}
	return fmt.Sprintf("%s (%s)", filepath.Base(secretPath), strings.Join(keys, ", "))
}

func ageenc(data string, publicKeys []string) (string, error) {
	recipients := make([]age.Recipient, 0, len(publicKeys))
	for _, publicKey := range publicKeys {
		recipient, err := age.ParseX25519Recipient(publicKey)
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
	identity, err := age.ParseX25519Identity(privateKey)
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
	if err := os.WriteFile(privatePath, []byte(identity.String()), 0o600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(publicPath, []byte(identity.Recipient().String()), 0o644); err != nil {
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

func new_secret(repo_dir string, key_names []string, secret_name string, secret string) (string, error) {
	keyDir, err := keyStore()
	if err != nil {
		return "", fmt.Errorf("access key store: %w", err)
	}
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
		publicKey, err := os.ReadFile(path.Join(keyDir, keyName+".pub"))
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
func read_secret(secret_dir string) (string, error) {
	// look at secret_dir/acl. find first also in keyStore
	// use that to decrypt "enc"
	keyDir, err := keyStore()
	if err != nil {
		return "", fmt.Errorf("cannot read secret from %q: %w", secret_dir, err)
	}

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
	_, err := keyStore()
	if err != nil {
		return nil, fmt.Errorf("cannot list keys: %w", err)
	}
	// TODO: list
	// maybe enum public, private, both
	// recursive find? or never allow keys with directory
	return make([]string, 0, 1), nil
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
