package sessions

import (
	"context"
	"encoding/json"
	"golang.org/x/sys/windows"
	"unsafe"
)

var wtsQuery = windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSQuerySessionInformationW")

type tokenStatistics struct {
	TokenID                                                                           windows.LUID
	AuthenticationID                                                                  windows.LUID
	Expiration                                                                        int64
	Type, Impersonation, DynamicCharged, DynamicAvailable, GroupCount, PrivilegeCount uint32
	ModifiedID                                                                        windows.LUID
}

func sessionText(id uint32, kind uint32) string {
	var value *uint16
	var bytes uint32
	ok, _, _ := wtsQuery.Call(0, uintptr(id), uintptr(kind), uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&bytes)))
	if ok == 0 || value == nil {
		return ""
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(value)))
	if bytes > 2048 {
		return ""
	}
	return windows.UTF16PtrToString(value)
}
func collect(ctx context.Context) ([]Session, bool, error) {
	var values *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &values, &count); err != nil {
		return nil, false, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(values)))
	result := []Session{}
	encodedBytes := 0
	for _, value := range unsafe.Slice(values, count) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		if value.State != windows.WTSActive && value.State != windows.WTSDisconnected {
			continue
		}
		if value.SessionID == 0 {
			continue
		}
		user := sessionText(value.SessionID, 5)
		if user == "" {
			continue
		}
		if len(result) == 64 {
			return result, true, nil
		}
		session := Session{ID: value.SessionID, Station: windows.UTF16PtrToString(value.WindowStationName), User: user, Domain: sessionText(value.SessionID, 7), State: "disconnected", Reason: "session_disconnected"}
		if value.State == windows.WTSActive {
			session.State, session.Reason = "active", "session_identity_unavailable"
			var token windows.Token
			if windows.WTSQueryUserToken(value.SessionID, &token) == nil {
				sid, logon, identityErr := tokenIdentity(token)
				if identityErr == nil {
					session.UserSID = sid
					session.LogonID = logon
					session.Selectable, session.Reason = true, ""
				}
				token.Close()
			}
		}
		encoded, _ := json.Marshal(session)
		if encodedBytes+len(encoded) > 65536 {
			return result, true, nil
		}
		encodedBytes += len(encoded)
		result = append(result, session)
	}
	return result, false, nil
}
