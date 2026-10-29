package session

import (
	"golang.org/x/sys/windows"
	"onecontrol/native/modules/user-session-host/internal/sessions"
)

type Target = sessions.Target

func Bind(target Target) (windows.Token, error) { return sessions.Bind(target) }
