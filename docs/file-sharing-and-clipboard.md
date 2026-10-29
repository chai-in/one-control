# File sharing and cross platform clipboard

Add optional file-transfer and clipboard modules for the Windows desktops and roaming Mac. They share device trust, encrypted channels, connection negotiation, user-session hosting and transfer persistence. They can be enabled independently. These are planned One Control implementations inspired by Blip and Universal Clipboard; interoperability with Blip or Apple's private continuity protocol is not assumed.

## File transfer scope

Target Blip's documented desktop experience: send files and nested folders without a preparation ZIP, preserve original quality, integrate drag-and-drop and right-click sending, transfer directly on the LAN or across the internet, and resume after interrupted networks, disconnected drives or full disks. Use no arbitrary product file-size cap; report actual filesystem, quota, free-space and transport limits. Support multiple transfers, per-device destinations, progress, pause/resume/cancel, history, notifications and explicit receiver decisions. Trusted own-device auto-accept is an opt-in policy.

Prefer an authenticated direct LAN connection, then an internet peer connection, then an end-to-end encrypted streaming relay. Keep negotiation separate from file bytes. The source and destination must be available for direct/relay transfer; queueing metadata does not imply offline file delivery. Optional encrypted store-and-forward requires its own storage, retention and cost settings. Cloudflare web hosting and RDP tunnels do not by themselves provide a general bulk-transfer relay.

Use chunk hashes, durable checkpoints, final whole-file verification and atomic destination commits. Resume validates the source identity/content before trusting old chunks. Handle destination name collisions, read-only/locked files, sparse/large files, Unicode and case collisions, macOS packages, symlinks, hard links and OS-specific metadata. Report metadata that cannot be represented on the other filesystem. Never follow an incoming path outside the selected destination or silently restore privileged ACLs. Benchmark direct and relay throughput, roaming, battery use and concurrency.

Blip also supports sending to other people, verified identity, invitations, discoverability controls and blocking. Preserve this as a separate optional sharing/contact module after own-device transfer, with explicit recipient authorization. It introduces identity and abuse-handling work beyond the initial personal-device pilot.

## Clipboard scope

Provide opt-in Mac to Windows and Windows to Windows copy/paste, on the same network or remotely. Start with text and images, then rich text/HTML and file/folder paste using the transfer engine. Use native pasteboard/clipboard adapters in the selected logged-in user session. The SYSTEM service's session is not the user's clipboard; RDP users and local users need explicit session targeting.

Offer direction controls, device groups, manual send, automatic sync, timed pause/resume, content-type controls and expiration. Prevent loops with origin/event identifiers and deterministic conflict handling. Do not overwrite a newer local copy with an older remote event. Exclude sensitive clipboard types where the OS/app marks them; provide password-manager and app exclusions, lock-screen behavior, office/personal boundaries and a visible status indicator. Secret detection cannot reliably identify every sensitive value. Clipboard history is independently optional with short retention and explicit clear controls.

Encrypt content end to end between authorized devices. Avoid logging clipboard bodies or retaining them on the coordinator. Large file clipboard items use on-demand transfer rather than copying whole folders into clipboard metadata. Clipboard synchronization across different computers is separate from clipboard redirection within an RDP session.

Apple Universal Clipboard supports Apple devices with the same Apple Account and nearby Handoff/Wi-Fi/Bluetooth requirements. Windows needs One Control's own bridge. Automatic iPhone system-wide clipboard monitoring is not promised by the iOS PWA: browser clipboard access is constrained by secure contexts, permissions and user interaction. Provide explicit foreground copy/paste and file selection where supported. Native iOS functionality would be a separate scope decision.

## Delivery and verification

Define transport and module contracts during the foundation work. Deliver own-device file transfer and basic native clipboard after the Windows/macOS user hosts exist; follow with rich formats, shell integration, external contacts and advanced transfer behavior. Verify genuine Mac/Windows round trips, Windows Server/RDP sessions, interrupted multi-gigabyte folders, Unicode/metadata handling, relay fallback, revocation, conflicts, suspend/resume and PWA foreground limits. Public relay hosting, region, throughput budget and egress costs remain feasibility decisions.

Sources checked on 19 October 2026: [Blip features](https://blip.net/), [Blip security](https://blip.net/security), [Apple Universal Clipboard](https://support.apple.com/en-us/102430), and [browser Clipboard API constraints](https://developer.mozilla.org/en-US/docs/Web/API/Clipboard_API).
