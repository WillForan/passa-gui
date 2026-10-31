package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path"

	"filippo.io/age"
	"filippo.io/age/armor"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
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
	w := a.NewWindow("Hello")

	hello := widget.NewLabel("Hello Fyne!")
	w.SetContent(container.NewVBox(
		hello,
		widget.NewButton("Hi!", func() {
			hello.SetText("Welcome :)")
		}),
	))

	w.ShowAndRun()
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
