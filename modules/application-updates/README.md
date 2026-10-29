# Application updates

The independently downloadable native host supports:

- `applications.check`: execute `winget --version` in one explicitly identified user logon and report availability.
- `applications.upgrade`: upgrade one exact package ID and pinned version from the WinGet source with user scope, silent execution and disabled interactivity. Independent approval binds the selected computer, SID, authentication LUID, package and version.

Source/package agreements use the organisation-default acceptance policy. The host does not request elevation, hash bypass, arbitrary installer switches or automatic reboot. It does not fall back to SYSTEM or another signed-in user. A missing/changed/elevated session fails before execution. An error after execution starts is indeterminate; it is never automatically replayed. No-applicable-update is an explicit unchanged outcome.

The shared session library is compiled into this optional host from the declared Go dependency. Only management-selected executable hosts are downloaded and activated. Select user-session discovery when operators need to obtain current logon identities in the console; installing application updates does not implicitly activate that separate feature.

Legacy `winget.upgrade` remains a compatibility command. Native callers use the explicit-session commands above. Installed-package inventory, update discovery, machine-scope approval policy and Store updates remain distinct work. API/browser acceptance uses fixture receipts; it does not establish that a real application was upgraded. No live application upgrades have been performed by this implementation's tests.

Microsoft CLI reference: [WinGet upgrade](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade).
