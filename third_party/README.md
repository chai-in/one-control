# Third-party source

The desktop policy adaptations and Falcon REST resource mappings identified in
`docs/sentry-integration.json` derive from TIBCON Sentry revision
`30799e4e2e57574521ddc628b338814ac2041bf8`. Upstream identifies TIBCON-owned code
as GPL-3.0-only. Its license is preserved in
`licenses/TIBCON-Sentry-GPL-3.0.txt`; adapted files carry SPDX identifiers.

These adaptations use One Control's scoped PostgreSQL authority and optional
module architecture. They do not include upstream credentials, runtime state,
mobile/CRM modules, fonts, bundled browser assets or the Windows Rust runtime.
Package dependencies retain the licenses distributed by their respective owners.
