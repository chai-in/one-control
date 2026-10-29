package packages

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func Identity(a Approval, attestation []byte) string {
	b, _ := json.Marshal(a)
	b = append(b, attestation...)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (d *Delivery) CheckAttestation(a Approval, attestation []byte, now int64) error {
	_, err := d.attest(a, attestation, now)
	return err
}

func (d *Delivery) verifyDirectory(directory string, a Approval, attestation []byte, now int64) error {
	p, err := d.attest(a, attestation, now)
	if err != nil {
		return err
	}
	info, err := d.parent.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid_published_directory")
	}
	root, err := d.parent.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("published_directory_replaced")
	}
	expected := map[string]bool{}
	dirs := map[string]bool{}
	for _, f := range p.Files {
		expected[f.Path] = true
		parts := strings.Split(f.Path, "/")
		for i := 1; i < len(parts); i++ {
			dirs[strings.Join(parts[:i], "/")] = true
		}
	}
	var walk func(string) error
	walk = func(dir string) error {
		f, e := root.Open(dir)
		if e != nil {
			return e
		}
		names, e := f.Readdirnames(d.options.Limits.Entries*8 + 1)
		ce := f.Close()
		if e != nil && e != io.EOF {
			return e
		}
		if ce != nil {
			return ce
		}
		if len(names) > d.options.Limits.Entries*8 {
			return errors.New("inventory_limit")
		}
		for _, name := range names {
			path := name
			if dir != "." {
				path = dir + "/" + name
			}
			if !portablePath(path) {
				return errors.New("invalid_inventory")
			}
			entry, e := root.Lstat(path)
			if e != nil {
				return e
			}
			if entry.Mode()&os.ModeSymlink != 0 {
				return errors.New("invalid_published_type")
			}
			if entry.IsDir() {
				if !dirs[path] {
					return errors.New("unexpected_published_directory")
				}
				if e = walk(path); e != nil {
					return e
				}
			} else if !entry.Mode().IsRegular() || !expected[path] {
				return errors.New("unexpected_published_file")
			}
		}
		return nil
	}
	if err = walk("."); err != nil {
		return err
	}
	for _, f := range p.Files {
		file, e := root.Open(f.Path)
		if e != nil {
			return e
		}
		before, e := file.Stat()
		if e != nil || !before.Mode().IsRegular() || before.Size() != f.Size {
			file.Close()
			return errors.New("published_size")
		}
		sum := sha256.New()
		n, e := io.Copy(sum, io.LimitReader(file, f.Size+1))
		current, se := root.Lstat(f.Path)
		ce := file.Close()
		if e != nil || se != nil || ce != nil || !os.SameFile(before, current) || current.Mode()&os.ModeSymlink != 0 || n != f.Size || hex.EncodeToString(sum.Sum(nil)) != f.SHA256 {
			return errors.New("published_hash")
		}
	}
	return nil
}

func (d *Delivery) Publish(r Receipt, a Approval, attestation []byte, now int64) (string, error) {
	if r.directory == "" || r.id != a.ID || r.version != a.Version || r.platform != a.Platform || r.digest != a.SHA256 {
		return "", errors.New("invalid_stage_receipt")
	}
	if err := d.verifyDirectory(r.directory, a, attestation, now); err != nil {
		return "", err
	}
	identity := Identity(a, attestation)
	name := "package-" + identity
	if _, err := d.parent.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("publication_exists")
	}
	if err := d.parent.Rename(r.directory, name); err != nil {
		return "", err
	}
	if err := d.verifyDirectory(name, a, attestation, now); err != nil {
		return "", err
	}
	return identity, nil
}

func (d *Delivery) VerifyPublished(a Approval, attestation []byte, now int64) error {
	return d.verifyDirectory("package-"+Identity(a, attestation), a, attestation, now)
}

func (d *Delivery) HasPublished(a Approval, attestation []byte) (bool, error) {
	_, err := d.parent.Lstat("package-" + Identity(a, attestation))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (d *Delivery) ControlsRoot(path string) bool {
	absolute, err := filepath.Abs(path)
	return err == nil && absolute == d.options.StagingRoot
}

func (d *Delivery) FixedExecutable(a Approval, attestation []byte, now int64) (string, error) {
	if a.Layout != "native-host-v1" || !strings.HasPrefix(a.Platform, "win-") {
		return "", errors.New("unsupported_host_shape")
	}
	if err := d.VerifyPublished(a, attestation, now); err != nil {
		return "", err
	}
	return filepath.Abs(filepath.Join(d.options.StagingRoot, "package-"+Identity(a, attestation), "bin", "host.exe"))
}

func (d *Delivery) Trash(a Approval, attestation []byte, now int64) error {
	if err := d.VerifyPublished(a, attestation, now); err != nil {
		return err
	}
	id := Identity(a, attestation)
	if _, err := d.parent.Lstat("trash-" + id); !errors.Is(err, os.ErrNotExist) {
		return errors.New("trash_exists")
	}
	return d.parent.Rename("package-"+id, "trash-"+id)
}

func (d *Delivery) FinishTrash(a Approval, attestation []byte, now int64) error {
	if err := d.CheckAttestation(a, attestation, now); err != nil {
		return err
	}
	id := Identity(a, attestation)
	_, err := d.parent.Lstat("package-" + id)
	if err == nil {
		if err = d.Trash(a, attestation, now); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return d.parent.RemoveAll("trash-" + id)
}
