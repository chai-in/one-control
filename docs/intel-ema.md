# Intel EMA reuse and retirement boundary

Imported and adapted design guidance. See phase 1 validation for current results. Source-era pilot observations remain historical evidence in the preserved transfer; they do not establish One Control deployment or live endpoint acceptance.

Keep Intel EMA as an independent backend. The One Control foundation's SYSTEM updater, user-session broker and optional IT console do not own EMA's service, database or AMT provisioning. Importing or retiring a management agent must preserve any independently managed EMA deployment.

## What is reused

The archived Sentry client establishes the OAuth `/api/token` password-grant flow and `/api/latest/endpoints` contract. V2 retains those contracts in an isolated, read-only server adapter. It uses bounded responses, TLS without redirects, a per-client in-memory token cache and one authentication refresh for reads. It does not persist EMA bearer tokens in the legacy Cloudflare KV cache.

Set `EMA_BASE_URL`, `EMA_USERNAME` and `EMA_PASSWORD` together through control-plane secret management. Use an existing appropriately scoped EMA account with read access to the required endpoint groups. The console and endpoint agent never receive these credentials. Authenticated viewers can call `GET /v1/integrations/ema/endpoints`, optionally with `?hostname=...`; the optional console has an Intel EMA inventory view. Missing configuration is reported explicitly, and unavailable upstream service returns a sanitized 503.

`IsConnected` describes the EMA software agent. `IsCiraConnected` describes the separate AMT tunnel. Unknown values remain unknown. EMA 1.15's live response includes null capability values and numeric AMT enums alongside the names shown in Intel's published examples; the adapter preserves both forms, and the console labels numeric values as EMA codes. Neither a Windows hostname nor a connected software agent establishes hardware identity or working out-of-band management. No EMA endpoint is automatically merged with a V2 device or targeted for a mutation by hostname.

The combined legacy Sentry-and-EMA bootstrapper is not carried forward. It installs and repairs the old agent alongside EMA and crosses the new modules' boundaries. Future EMA installation must use an independent, signed and reviewed deployment package. Power operations, remote desktop, provisioning changes and agent removal require a separate authorization, audit and acceptance design before they are exposed in V2.

API reference: [Intel EMA REST API](https://www.intel.com/content/dam/support/us/en/documents/software/manageability-products/Latestswagger.html).

## Preservation and acceptance

Do not modify existing EMA services, database, certificates, profiles, provisioning or connectivity as part of this import. Site-specific addresses and historical verification remain in the preserved transfer. One Control needs fresh configuration and live acceptance before claiming connectivity or hardware AMT recovery.
