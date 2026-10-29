# User sessions

The optional native host handles `sessions.list`. Windows Terminal Services supplies active and disconnected console/RDP sessions. Only a verified active session exposes a selectable SID and authentication LUID; a recycled numeric session ID is insufficient. The console expires discovery results after five minutes and binds a user operation to one computer.

The `native/session` package is an explicit source dependency of application updates. Its code is compiled into that optional application host; it is not a separately activated shared runtime. The discovery host is selected independently. Executable feature packages cannot masquerade as passive shared catalog dependencies.

For selected-user execution, the SYSTEM broker obtains that exact session's primary token, rejects an elevated token, creates the user's environment, and starts a suspended process without inherited handles. It assigns a kill-on-close job, rechecks the logon, then resumes. It checks session continuity while running and terminates its job on cancellation. It never chooses the console user as a fallback. Installer-service effects cannot be rolled back by terminating this process; uncertain execution remains indeterminate.

The current process entry point is the selected user's WinGet alias, with arguments supplied by the application-update command parser. No arbitrary executable or command-line API is exposed. Clipboard, file transfer and long-lived user hosts remain separate work.

Read-only WTS collection and nonexistent-session rejection run locally. The signed SYSTEM installation pilot exercises this host through native dispatch; actual standard-user WinGet execution and logon-switch acceptance remain separate live pilot gates.

Microsoft API reference: [WTSQueryUserToken](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken).
