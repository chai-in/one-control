package sessions

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

// Target binds an operation to a logon, not merely a reusable numeric session ID.
type Target struct {
	SessionID uint32 `json:"sessionId"`
	UserSID   string `json:"userSid"`
	LogonID   string `json:"logonId"`
}

func tokenIdentity(token windows.Token) (string, string, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return "", "", err
	}
	var stats tokenStatistics
	var returned uint32
	if err = windows.GetTokenInformation(token, windows.TokenStatistics, (*byte)(unsafe.Pointer(&stats)), uint32(unsafe.Sizeof(stats)), &returned); err != nil {
		return "", "", err
	}
	if returned != uint32(unsafe.Sizeof(stats)) {
		return "", "", errors.New("invalid_token_statistics")
	}
	return user.User.Sid.String(), fmt.Sprintf("%08x%08x", uint32(stats.AuthenticationID.HighPart), stats.AuthenticationID.LowPart), nil
}
func Bind(target Target) (windows.Token, error) {
	var values *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &values, &count); err != nil {
		return 0, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(values)))
	active := false
	for _, session := range unsafe.Slice(values, count) {
		if session.SessionID == target.SessionID && session.State == windows.WTSActive {
			active = true
			break
		}
	}
	if !active {
		return 0, errors.New("selected_session_not_active")
	}
	var token windows.Token
	if err := windows.WTSQueryUserToken(target.SessionID, &token); err != nil {
		return 0, err
	}
	sid, logon, err := tokenIdentity(token)
	if err != nil || sid != target.UserSID || logon != target.LogonID {
		token.Close()
		return 0, errors.New("selected_session_changed")
	}
	return token, nil
}
