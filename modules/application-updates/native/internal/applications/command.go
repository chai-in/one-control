package applications

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

type target struct {
	SessionID uint32 `json:"sessionId"`
	UserSID   string `json:"userSid"`
	LogonID   string `json:"logonId"`
}
type command struct {
	Kind      string `json:"kind"`
	PackageID string `json:"packageId,omitempty"`
	Version   string `json:"version,omitempty"`
	Session   target `json:"session"`
}

var packageID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var version = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+()-]{0,63}$`)
var sid = regexp.MustCompile(`^S-1-[0-9]+(?:-[0-9]+){1,15}$`)
var logon = regexp.MustCompile(`^[a-f0-9]{16}$`)

func parse(raw []byte) (command, []string, error) {
	var input command
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	invalid := errors.New("invalid_application_command")
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.Session.SessionID == 0 || !sid.MatchString(input.Session.UserSID) || !logon.MatchString(input.Session.LogonID) {
		return input, nil, invalid
	}
	switch input.Kind {
	case "applications.check":
		if input.PackageID != "" || input.Version != "" {
			return input, nil, invalid
		}
		return input, []string{"--version"}, nil
	case "applications.upgrade":
		if !packageID.MatchString(input.PackageID) || !version.MatchString(input.Version) || strings.EqualFold(input.Version, "latest") || strings.EqualFold(input.Version, "unknown") {
			return input, nil, invalid
		}
		return input, []string{"upgrade", "--id", input.PackageID, "--exact", "--version", input.Version, "--source", "winget", "--scope", "user", "--silent", "--disable-interactivity", "--accept-source-agreements", "--accept-package-agreements"}, nil
	default:
		return input, nil, invalid
	}
}
