module onecontrol/native/modules/application-updates

go 1.27.2

require (
	onecontrol/native v0.0.0
	onecontrol/native/modules/user-session-host v0.0.0
)

require golang.org/x/sys v0.49.0 // indirect

replace onecontrol/native => ../../../native

replace onecontrol/native/modules/user-session-host => ../../user-session-host/native
