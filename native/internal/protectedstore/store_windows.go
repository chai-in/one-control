package protectedstore

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func trusted(sid *windows.SID) bool {
	switch sid.String() {
	case "S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464":
		return true
	}
	return false
}

// Check rejects replaceable ancestors, reparse traversal, and untrusted access.
// Ancestors may permit child creation; the selected private leaf may not.
func Check(path string, private bool) error {
	mode := 1
	if private {
		mode = 2
	}
	return check(path, mode)
}

func check(path string, mode int) error {
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) {
		return errors.New("protected_local_path_required")
	}
	path = filepath.Clean(path)
	leaf := true
	for {
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		attrs, err := windows.GetFileAttributes(p)
		if err != nil {
			return err
		}
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("protected_path_reparse_point")
		}
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		owner, _, err := sd.Owner()
		if err != nil || owner == nil || !trusted(owner) {
			return errors.New("protected_path_owner")
		}
		acl, _, err := sd.DACL()
		if err != nil || acl == nil {
			return errors.New("protected_path_dacl")
		}
		for index := uint32(0); index < uint32(acl.AceCount); index++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err = windows.GetAce(acl, index, &ace); err != nil {
				return err
			}
			if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
				continue
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
				return errors.New("protected_path_unsupported_ace")
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if trusted(sid) {
				continue
			}
			const fileDeleteChild = 0x40
			mask := uint32(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | fileDeleteChild | windows.GENERIC_ALL | windows.GENERIC_WRITE)
			if leaf && mode > 0 {
				mask |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
				if mode == 2 {
					mask = ^uint32(0)
				}
			}
			if uint32(ace.Mask)&mask != 0 {
				return errors.New("protected_path_untrusted_access")
			}
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path, leaf = parent, false
	}
}

func Create(path string) error {
	if err := check(filepath.Dir(path), 0); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(p, &sa)
	runtime.KeepAlive(sd)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	return Check(path, true)
}

func replace(source, destination string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func protect(data []byte, decrypt bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty_protected_secret")
	}
	input := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var output windows.DataBlob
	var err error
	if decrypt {
		err = windows.CryptUnprotectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	} else {
		err = windows.CryptProtectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN|windows.CRYPTPROTECT_LOCAL_MACHINE, &output)
	}
	runtime.KeepAlive(data)
	if err != nil {
		return nil, errors.New("machine_secret_protection_failed")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	result := append([]byte(nil), unsafe.Slice(output.Data, int(output.Size))...)
	clear(unsafe.Slice(output.Data, int(output.Size)))
	return result, nil
}
func seal(data []byte) ([]byte, error)   { return protect(data, false) }
func unseal(data []byte) ([]byte, error) { return protect(data, true) }
