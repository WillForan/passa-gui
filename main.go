package main

import (
        "log"
        "path"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
        "filippo.io/age"
        "github.com/go-git/go-git/v6"
        "github.com/adrg/xdg"
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

func dcrypt(pkey, data_file) {
	identity, err := age.ParseX25519Identity(pkey)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	f, err := os.Open(data_file)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}

	r, err := age.Decrypt(f, identity)
	if err != nil {
		log.Fatalf("Failed to open encrypted file: %v", err)
	}
	out := &bytes.Buffer{}
	if _, err := io.Copy(out, r); err != nil {
		log.Fatalf("Failed to read encrypted file: %v", err)
	}

	fmt.Printf("File contents: %q\n", out.Bytes())
}

func gitpull(name, remote_loc) {
  store_dir = path.Join(xdg.DataDirs, "passa-gui", name)
  _, err := git.PlainClone(store_dir, &git.CloneOptions{
      URL:      remote_loc,
      Progress: os.Stdout,
  })
}
