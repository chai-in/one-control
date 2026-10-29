# Private-alpha RDP handoff reference

`native/internal/rdp` is a pure Go formatter for a future optional native-client feature. It has no bootstrap dependency, installation, file write, process launch, DNS lookup, or network access. It does not constitute an installed module.

```go
type Descriptor struct {
	Host string
	Port int
}

type ManualTarget struct {
	Host string
	Port uint16
}

func FormatWindowsFile(Descriptor) ([]byte, error)
func FormatManualTarget(Descriptor) (ManualTarget, error)
```

Both functions validate every call. An invalid descriptor returns `ErrInvalidDescriptor`, a static error without input data. Windows output is nil on error. Manual output is the zero value on error. Each successful Windows call returns its own mutable byte slice.

## Accepted targets

`Port` must be 1 through 65535 before conversion to `uint16`. `Host` accepts canonical dotted IPv4 or ASCII DNS names of at most 253 bytes. DNS labels contain 1 through 63 bytes, use only ASCII letters, digits, and interior hyphens, and end with a letter or digit. The final label must begin with an ASCII letter. This intentionally narrow policy rejects numeric aliases and alternative IPv4 spellings that clients might interpret differently. DNS letters become lowercase after validation.

IPv6, bracketed literals, zones, trailing dots, Unicode, whitespace, control characters, user information, credentials, URIs, paths, queries, fragments, percent escapes, embedded ports, and launch arguments are rejected. The formatter does not trim, resolve, decode, or repair input.

The typed API accepts no settings map, display option, username, credential, token, URI, or executable argument. There is no untyped decoder. A future external decoder must reject unknown fields before creating a descriptor. Its server must separately prove current target and session authority. Successful formatting grants no authority.

## Windows output

`FormatWindowsFile` returns exactly these four ASCII lines with CRLF after every line, including the last. The first line contains the validated host and decimal port.

```text
full address:s:pc.example:3389
authentication level:i:1
enablecredsspsupport:i:1
redirectclipboard:i:0
```

Microsoft documents `.rdp` connection files for [Remote Desktop Connection](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc). Its [RDP property reference](https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-properties) applies to remote-PC files. Authentication level 1 refuses failed server authentication. CredSSP remains enabled when available. Clipboard redirection is disabled. Callers cannot override these values.

Enabling CredSSP does not enforce server NLA. An actual client and server pilot must prove NLA enforcement and refusal of certificate failures. The four properties do not claim to configure every redirection or security policy.

## macOS output

`FormatManualTarget` returns the validated host and numeric port separately. Microsoft's current [Windows App remote-PC instructions](https://learn.microsoft.com/en-us/windows-app/get-started-connect-devices-desktops-apps?pivots=remote-pc) document **Add PC** with a hostname or IP address. This manual flow is the supported fallback. Exact nondefault-port entry and client security settings remain pilot requirements.

The formatter exports no macOS URI or file handoff. Microsoft's [legacy URI reference](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remote-desktop-uri) and [retired macOS client file-import reference](https://learn.microsoft.com/en-us/previous-versions/remote-desktop-client/remote-desktop-macos) do not establish current Windows App acceptance or equivalent security settings.

Windows credentials belong only in the installed RDP client's authentication flow. One Control device tokens, bearer tokens, private keys, and reusable tunnel credentials have no place in these outputs or related logs. Manual setup cannot enforce client settings.

## Verification limits

Portable tests prove formatting, target rejection, fixed properties, deterministic output, and independent output ownership. They do not prove file association, installed-client acceptance, certificate handling, NLA enforcement, route approval, clipboard behavior, target authorization, or authenticated connectivity. Those checks remain open on actual Windows and macOS clients and the home target. A client path that requires a certificate or NLA bypass fails acceptance.

Server authorization, fresh target delivery, optional-module packaging, client UI, Cloudflare routing, installation, and the home acceptance pilot remain separate integration work. Browser RDP and physical-desktop control remain later scope.
