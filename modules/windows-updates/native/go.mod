module onecontrol/native/modules/windows-updates

go 1.27.2

require (
	github.com/go-ole/go-ole v1.3.0
	onecontrol/native v0.0.0
)

require golang.org/x/sys v0.49.0 // indirect

replace onecontrol/native => ../../../native
