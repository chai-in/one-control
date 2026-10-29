# Windows release signing

Imported and adapted design guidance. See phase 1 validation for current results. Source-era pilot observations remain historical evidence in the preserved transfer; they do not establish One Control deployment or live endpoint acceptance.

An offline RSA-PSS release key authorizes package metadata. Authenticode separately authenticates the Windows executable or MSI. Both checks are required; access to one signing key does not replace the other.

## Internal trust for the POC

Microsoft company verification and a publicly trusted signing certificate are not prerequisites for this controlled POC. A separately approved internal certificate can sign selected pilot releases, with an explicit publisher pin and certificate trust on each approved computer. Both the signed release envelope and Authenticode checks remain mandatory. Use the explicit `-InternalTestSigning` profile; do not export the private key or silently fall back to internal signing after another profile fails.

An internal certificate does not create an exception in Smart App Control. Smart App Control has [no individual-app allowlist](https://support.microsoft.com/en-us/windows/security/threat-malware-protection/smart-app-control-frequently-asked-questions). A company-managed [App Control for Business policy](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/create-appcontrol-policy-for-lightly-managed-devices) can explicitly allow internally signed applications. Any policy deployment is a separate administrator action requiring target-specific acceptance. The agent and installer must never weaken security policy themselves.

Broad deployment remains subject to business approval. Public signing is an optional distribution route, and a managed internal-PKI deployment is another route; neither substitutes for endpoint execution and recovery acceptance. Internal test signing requires explicit approval for a named pilot.

## Optional public signing route

Microsoft's [Smart App Control signing guidance](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/code-signing-for-smart-app-control) describes its trusted-provider requirements. A signature accepted on an explicitly trusting pilot computer does not establish SAC acceptance elsewhere.

Production signing identity and procurement remain unconfigured for One Control. Verify provider eligibility, identity validation, hardware-backed key storage and cost before selecting a service.

Recheck signing-provider geographic eligibility at procurement time. A supported Windows certificate-store/KSP integration can use the signing script; other services require an adapter and acceptance.

## Reproducible build and signing

Use the SDK pinned in `global.json`, a Microsoft-signed Windows SDK SignTool, and WiX 4 for MSI packaging. Publish locks are separate from ordinary build locks because self-contained single-file output resolves runtime-specific dependencies. Never regenerate these locks silently during release publication.

```powershell
$releaseVersion = (xml).Project.PropertyGroup.Version
./scripts/publish-agent.ps1 -OutputDirectory C:\IT\OneControlRelease
./scripts/sign-agent.ps1 -ReleaseDirectory C:\IT\OneControlRelease `
  -PublisherThumbprint <approved-certificate-thumbprint> `
  -SignTool 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
New-Item -ItemType Directory -Path C:\IT\OneControlPayload
./scripts/package-agent.ps1 -ReleaseDirectory C:\IT\OneControlRelease `
  -Version $releaseVersion `
  -OutputFile (Join-Path C:\IT\OneControlPayload ('one-control-agent-'+$releaseVersion+'.msi'))
./scripts/sign-agent.ps1 -ReleaseDirectory C:\IT\OneControlPayload `
  -PublisherThumbprint <approved-certificate-thumbprint> `
  -SignTool 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
```

Check each script's parameters for an explicit output version or alternate tool path. Production mode rejects self-signed certificates and requires a current code-signing EKU, private key and trusted revocation-checked chain. `-InternalTestSigning` is an explicit pilot-only exception, recorded in `signing.json`; it is never a fallback after failed production signing. A hardware-backed certificate may prompt through its provider; keep approval and token authentication outside repository configuration.

Signing preserves valid vendor signatures and already valid, timestamped selected-publisher signatures. It verifies the final signature and timestamp, then writes checksums of the actual signed bytes. The RFC 3161 endpoint defaults to Microsoft's documented `http://timestamp.digicert.com` example; the response and final signature are cryptographically verified with [SignTool](https://learn.microsoft.com/en-us/windows/desktop/seccrypto/signtool). A timestamp failure fails the release. Choose a supported alternative endpoint explicitly rather than weakening validation.

Stage-only MSI versions follow [Windows Installer ProductVersion limits](https://learn.microsoft.com/en-us/windows/win32/msi/productversion): major/minor at most 255 and build at most 65535. The package contains versioned files and markers only. It has no custom actions or service operations. Its immutable version directory must not already exist on the target.

Construct release metadata only after signing the MSI. Verify its SHA-256 and exact byte size against the registered envelope immediately before publication. Never re-sign an artifact after registering its hash: publish a new immutable artifact and sequence if bytes change. Keep the RSA private key offline; retain only its public key at the control plane and endpoints. Do not sign a directory containing previously published releases as part of preparing a new release.

## Required acceptance after public certificate enrollment

Repeat initial provisioning and signed self-update on a computer enforcing Smart App Control, using the new public publisher pin without changing that computer's security policy. Test publisher rejection, timestamp/chain validation, native dependency execution, unhealthy-candidate rollback and credential continuity. Internal pilot results remain useful recovery evidence, but cannot substitute for the public-trust execution test.
