package main

import (
	"bytes"
	"io"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
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
		name     string
		identity age.Identity
	}{
		{name: "first recipient", identity: firstIdentity},
		{name: "second recipient", identity: secondIdentity},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			reader := armor.NewReader(bytes.NewBufferString(encrypted))
			decrypted, err := age.Decrypt(reader, testCase.identity)
			if err != nil {
				t.Fatal(err)
			}

			got, err := io.ReadAll(decrypted)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != plaintext {
				t.Fatalf("decrypted plaintext = %q, want %q", got, plaintext)
			}
		})
	}
}
