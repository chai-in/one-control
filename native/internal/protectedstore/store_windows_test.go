package protectedstore

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func protectedFixture(t *testing.T) string {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		if os.Getenv("CI") == "true" {
			t.Fatal("protected storage acceptance requires an elevated Windows runner")
		}
		t.Skip("requires elevated Windows; mandatory in Windows CI")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(os.Getenv("ProgramData"), "OneControlStorageTest-"+hex.EncodeToString(nonce))
	if err := Create(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	return root
}

func TestMachineSecretCustody(t *testing.T) {
	root := protectedFixture(t)
	path := filepath.Join(root, "credential.dpapi")
	original := []byte("disposable test credential, not a real enrollment")
	for _, value := range [][]byte{original, []byte("replacement disposable credential")} {
		if err := WriteSecret(path, value); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil || bytes.Contains(raw, value) {
			t.Fatal("credential was not sealed")
		}
		actual, err := ReadSecret(path)
		if err != nil || !bytes.Equal(actual, value) {
			t.Fatal("protected credential roundtrip failed", err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err = Write(path, raw); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadSecret(path); err == nil {
		t.Fatal("tampered DPAPI payload accepted")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatal("replacement left pending files", err)
	}
}

func TestRejectWorldReadableAndReparseStorage(t *testing.T) {
	root := protectedFixture(t)
	path := filepath.Join(root, "public.json")
	if err := Write(path, []byte(`{"fixture":true}`)); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = Read(path, 1024); err == nil {
		t.Fatal("world-readable private file accepted")
	}
	if err = Write(path, []byte(`{}`)); err == nil {
		t.Fatal("unprotected existing file replaced")
	}
	target := filepath.Join(root, "target")
	if err = Create(target); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err = os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err = Check(link, true); err == nil {
		t.Fatal("reparse point accepted")
	}
}
