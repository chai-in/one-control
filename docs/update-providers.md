# Provider coverage and acceptance

Imported and adapted design guidance. See phase 1 validation for current results. Source-era pilot observations remain historical evidence in the preserved transfer; they do not establish One Control deployment or live endpoint acceptance.

| Provider | Implemented operation | First-release limit |
| --- | --- | --- |
| Windows Update | Scan, then install exact update IDs and revisions through WUA COM | Respects WSUS; excludes drivers/feature upgrades/prompts; accepts terms for exact approved updates under organisation policy; no forced reboot |
| WinGet | Upgrade an exact package ID to an exact version in the active user's context | Organisation policy accepts source/package terms by default; no bulk `--all`, unpinned versions, pin override or privilege escalation |
| Microsoft Store | Exact Store catalogue product through `winget --source msstore`; source/package terms accepted by default | Does not claim to update every UWP/Store app; native Store-wide orchestration needs a tested provider |
| Internal applications | Signed, allowlisted, Authenticode-verified MSI | Installer receipts; reconcile installed version with inventory before declaring app healthy |
| Agent self-update | Signed stage-only MSI, independent SYSTEM recovery service, version/path/PID-bound authenticated health and rollback | Requires running `OneControlRecovery`; preserves previous payloads and identity/journal; an interrupted MSI is quarantined, never replayed |
| Drivers / firmware / BIOS | Roadmap | Vendor-specific signing, recovery, AC power and hardware testing required |
| Browsers, runtimes, Office, VPN, printer tools | WinGet or signed MSI where supported | Create a controlled app catalogue and validate detection/health per application |

The imported foundation contains these adapters. Current validation is in the phase 1 report; source-era live tests remain archived and do not establish One Control endpoint acceptance.

## Required Windows pilot

Use a company-owned Windows 11 test computer with the existing CrowdStrike sensor. Test real SYSTEM service installation and cold boot, outbound TLS trust, enrollment failure/recovery, revocation, token rotation, inventory, WUA scan, an explicitly approved test update, pending reboot reporting, a WinGet test app and its source agreements, a supported Store app, standard-user permissions, signed MSI publisher rejection, failed download, network loss during installation, power loss, service restart, broker startup in a real user session, and recovery of indeterminate jobs. Confirm no tray/window appears for floor staff.

Agent self-update uses the independent recovery host described in [operations](operations.md#agent-update-and-recovery). Its live acceptance includes an unhealthy signed candidate and a recovery-process crash while Windows Installer continued. Physical power loss, fleet-wide policy combinations and recovery-host upgrades remain separate acceptance work. Generic MSI installer exit codes alone do not establish successful self-update or app health.

Before distributing the optional console, validate organisation sign-in, viewer/operator/approver separation, session expiry, log-out, keyboard navigation, and an actual two-person canary ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ pilot ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÂ¢Ã¢â€šÂ¬Ã¢â€žÂ¢ broad promotion.
