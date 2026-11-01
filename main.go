package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"image/color"
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
	keys, err := list_keys()
	if err != nil {
		keys = []string{}
	}
	selectedKeys := make(map[string]bool)
	keyList := widget.NewList(
		func() int { return len(keys) },
		func() fyne.CanvasObject { return widget.NewCheck("", nil) },
		func(id widget.ListItemID, object fyne.CanvasObject) {
			check := object.(*widget.Check)
			keyName := keys[id]
			check.SetText(keyName)
			check.SetChecked(selectedKeys[keyName])
			check.OnChanged = func(checked bool) {
				selectedKeys[keyName] = checked
			}
		},
	)
	repoList := widget.NewList(
		func() int { return len(repos) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, object fyne.CanvasObject) {
			object.(*widget.Label).SetText(filepath.Base(repos[id]))
		},
	)

	secrets := []string{}
	currentRepo := ""
	currentSecret := ""
	var secretList *widget.List
	secretList = widget.NewList(
		func() int { return len(secrets) + 1 },
		func() fyne.CanvasObject {
			item := &secretListItem{
				onCopyPassword: func(string) {},
				onCopyLocation: func(string) {},
				onSelect:       func() {},
			}
			item.Label = *widget.NewLabel("")
			return item
		},
		func(id widget.ListItemID, object fyne.CanvasObject) {
			item := object.(*secretListItem)
			if id == 0 {
				item.secretPath = ""
				item.SetText("[none selected]")
				item.onSelect = func() {
					secretList.Select(0)
				}
				return
			}
			item.secretPath = secrets[id-1]
			item.SetText(secretListText(item.secretPath))
			item.onSelect = func() {
				secretList.Select(id)
			}
			item.onCopyPassword = func(secretPath string) {
				secret, err := read_secret(secretPath)
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				a.Clipboard().SetContent(secret)
			}
			item.onCopyLocation = func(secretPath string) {
				a.Clipboard().SetContent(secretPath)
			}
		},
	)
	secretDisplay := widget.NewMultiLineEntry()
	secretDisplay.SetMinRowsVisible(8)
	secretPathLabel := widget.NewLabel("")
	secretPathLabel.Selectable = true
	changeButton := widget.NewButton("Change", nil)
	copyButton := widget.NewButton("Copy", nil)
	totpButton := widget.NewButton("TOTP", nil)

	refreshKeys := func() {
		updated, err := list_keys()
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		keys = updated
		for keyName := range selectedKeys {
			if !contains(keys, keyName) {
				delete(selectedKeys, keyName)
			}
		}
		keyList.Refresh()
	}
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
		currentSecret = ""
		secretPathLabel.SetText("")
		secretDisplay.SetText("")
	}

	repoList.OnSelected = func(id widget.ListItemID) {
		if id < len(repos) {
			currentRepo = repos[id]
			refreshSecrets(repos[id])
		}
	}
	secretList.OnSelected = func(id widget.ListItemID) {
		if id == 0 {
			currentSecret = ""
			secretPathLabel.SetText("")
			secretDisplay.SetText("")
			secretDisplay.Refresh()
			return
		}
		if id > len(secrets) {
			return
		}
		secret, err := read_secret(secrets[id-1])
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		acl, err := os.ReadFile(filepath.Join(secrets[id-1], "acl"))
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		selectedKeys = make(map[string]bool)
		for _, line := range strings.Split(string(acl), "\n") {
			if keyName := aclKeyName(line); keyName != "" && contains(keys, keyName) {
				selectedKeys[keyName] = true
			}
		}
		keyList.Refresh()
		currentSecret = secrets[id-1]
		secretPathLabel.SetText(currentSecret)
		secretDisplay.SetText(secret)
		secretDisplay.Refresh()
	}

	repoAddButton := widget.NewButton("Add Store", nil)
	repoAddButton.OnTapped = func() {
		menu := fyne.NewMenu("",
			fyne.NewMenuItem("Load existing directory", func() {
				dialog.ShowInformation("Not implemented", "Storing an existing directory is not implemented yet.", w)
			}),
			fyne.NewMenuItem("Import git clone", func() {
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
		widget.ShowPopUpMenuAtRelativePosition(menu, w.Canvas(), fyne.NewPos(0, repoAddButton.Size().Height), repoAddButton)
	}

	keyAddButton := widget.NewButton("New Key", nil)
	keyAddButton.OnTapped = func() {
		menu := fyne.NewMenu("",
			fyne.NewMenuItem("Generate new", func() {
				dialog.ShowEntryDialog("New key", "Key name", func(name string) {
					name = strings.TrimSpace(name)
					if _, err := new_key(name); err != nil {
						dialog.ShowError(err, w)
						return
					}
					refreshKeys()
				}, w)
			}),
			fyne.NewMenuItem("Import from file", func() {
				dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
					if err != nil {
						dialog.ShowError(err, w)
						return
					}
					defer reader.Close()
					data, err := io.ReadAll(reader)
					if err != nil {
						dialog.ShowError(err, w)
						return
					}
					keyName := reader.URI().Name()
					if _, err := import_key(keyName, string(data)); err != nil {
						dialog.ShowError(err, w)
						return
					}
					refreshKeys()
				}, w)
			}),
		)
		widget.ShowPopUpMenuAtRelativePosition(menu, w.Canvas(), fyne.NewPos(0, keyAddButton.Size().Height), keyAddButton)
	}

	secretAddButton := widget.NewButton("New Secret", nil)
	secretAddButton.OnTapped = func() {
		if currentRepo == "" {
			dialog.ShowInformation("Select a repository", "Select a repository before adding a secret.", w)
			return
		}
		keyNames := make([]string, 0, len(keys))
		for _, keyName := range keys {
			if selectedKeys[keyName] {
				keyNames = append(keyNames, keyName)
			}
		}
		if len(keyNames) == 0 {
			dialog.ShowInformation("Select keys", "Select at least one key before adding a secret.", w)
			return
		}
		dialog.ShowEntryDialog("New secret", "Secret name", func(name string) {
			name = strings.TrimSpace(name)
			if _, err := new_secret(currentRepo, keyNames, name, ""); err != nil {
				dialog.ShowError(err, w)
				return
			}
			refreshSecrets(currentRepo)
		}, w)
	}

	changeButton.OnTapped = func() {
		if currentSecret == "" {
			dialog.ShowInformation("Select a secret", "Select a secret before changing it.", w)
			return
		}
		keyNames := make([]string, 0, len(keys))
		for _, keyName := range keys {
			if selectedKeys[keyName] {
				keyNames = append(keyNames, keyName)
			}
		}
		if len(keyNames) == 0 {
			dialog.ShowInformation("Select keys", "Select at least one key before changing the secret.", w)
			return
		}
		if err := updateSecret(currentSecret, keyNames, secretDisplay.Text); err != nil {
			dialog.ShowError(err, w)
			return
		}
		if err := commitSecretChange(currentRepo, currentSecret); err != nil {
			dialog.ShowError(err, w)
			return
		}
		changedSecret := currentSecret
		refreshSecrets(currentRepo)
		secretList.UnselectAll()
		for id, secretPath := range secrets {
			if secretPath == changedSecret {
				secretList.Select(widget.ListItemID(id + 1))
				break
			}
		}
	}
	totpButton.OnTapped = func() {
		code, err := generateTOTP(secretDisplay.Text)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		a.Clipboard().SetContent(code)
		codeLabel := widget.NewLabel(code)
		codeLabel.Selectable = true
		dialog.ShowCustom("TOTP", "Close", container.NewVBox(
			codeLabel,
			widget.NewLabel("Copied to clipboard."),
		), w)
	}
	copyButton.OnTapped = func() {
		if currentSecret == "" {
			dialog.ShowInformation("Select a secret", "Select a secret before copying it.", w)
			return
		}
		a.Clipboard().SetContent(secretDisplay.Text)
	}

	repoPane := container.NewBorder(paneHeader("Repositories"), repoAddButton, nil, nil, repoList)
	keyPane := container.NewBorder(paneHeader("Keys"), keyAddButton, nil, nil, keyList)
	w.SetOnDropped(func(position fyne.Position, uris []fyne.URI) {
		keyPanePosition := keyPane.Position()
		keyPaneSize := keyPane.Size()
		if position.X < keyPanePosition.X || position.Y < keyPanePosition.Y ||
			position.X > keyPanePosition.X+keyPaneSize.Width ||
			position.Y > keyPanePosition.Y+keyPaneSize.Height {
			return
		}
		for _, uri := range uris {
			reader, err := storage.Reader(uri)
			if err != nil {
				dialog.ShowError(err, w)
				continue
			}
			data, readErr := io.ReadAll(reader)
			closeErr := reader.Close()
			if readErr != nil {
				dialog.ShowError(readErr, w)
				continue
			}
			if closeErr != nil {
				dialog.ShowError(closeErr, w)
				continue
			}
			if _, err := import_key(uri.Name(), string(data)); err != nil {
				dialog.ShowError(err, w)
				continue
			}
			refreshKeys()
		}
	})
	leftPane := container.NewVSplit(repoPane, keyPane)
	leftPane.Offset = 0.4
	middlePane := container.NewBorder(paneHeader("Secrets"), secretAddButton, nil, nil, secretList)
	secretContent := container.NewBorder(secretPathLabel, nil, nil, nil, secretDisplay)
	rightPane := container.NewBorder(paneHeader("Secret"), container.NewHBox(changeButton, copyButton, totpButton), nil, nil, secretContent)
	leftMiddle := container.NewHSplit(leftPane, middlePane)
	leftMiddle.Offset = 0.3
	mainSplit := container.NewHSplit(leftMiddle, rightPane)
	mainSplit.Offset = 0.5
	w.SetContent(mainSplit)
	if len(repos) > 0 {
		repoList.Select(0)
	}

	w.ShowAndRun()
}

func paneHeader(title string) fyne.CanvasObject {
	background := canvas.NewRectangle(theme.PrimaryColor())
	label := canvas.NewText(title, color.Black)
	label.TextStyle = fyne.TextStyle{Bold: true}
	return container.NewMax(background, label)
}

type secretListItem struct {
	widget.Label
	secretPath     string
	onCopyPassword func(string)
	onCopyLocation func(string)
	onSelect       func()
}

func (item *secretListItem) Tapped(*fyne.PointEvent) {
	item.onSelect()
}

func (item *secretListItem) TappedSecondary(event *fyne.PointEvent) {
	if item.secretPath == "" {
		return
	}
	menu := fyne.NewMenu("",
		fyne.NewMenuItem("Password to clipboard", func() {
			item.onCopyPassword(item.secretPath)
		}),
		fyne.NewMenuItem("Location to clipboard", func() {
			item.onCopyLocation(item.secretPath)
		}),
	)
	canvas := fyne.CurrentApp().Driver().CanvasForObject(item)
	widget.ShowPopUpMenuAtPosition(menu, canvas, event.AbsolutePosition)
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func secretListText(secretPath string) string {
	acl, err := os.ReadFile(filepath.Join(secretPath, "acl"))
	if err != nil {
		return filepath.Base(secretPath)
	}
	keys := make([]string, 0)
	for _, line := range strings.Split(string(acl), "\n") {
		if keyName := aclKeyName(line); keyName != "" {
			keys = append(keys, keyName)
		}
	}
	if len(keys) == 0 {
		return filepath.Base(secretPath)
	}
	return fmt.Sprintf("%s (%s)", filepath.Base(secretPath), strings.Join(keys, ", "))
}
