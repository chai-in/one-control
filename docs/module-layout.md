# Module source layout

Each optional feature has a `modules/<id>/` folder. Server handlers, console views,
native providers and Windows compatibility providers live below `server/`,
`console/`, `native/` and `windows/` respectively. A folder contains only the parts
implemented for that feature. A registration alone is not a finished provider.

`module.json` indexes the source version and exact source dependencies.
`definition.ts` registers server permissions and entrypoints. Package manifests
declare build dependencies. Signed release catalogs separately declare immutable
artifact versions, exact runtime dependencies, hashes, permissions and host ABI.
Source metadata never grants permission to download or execute a package.

The server build includes every public module's implemented server code and console
views. All optional features start disabled. The endpoint installer contains only
the native bootstrap. It obtains selected feature packages and their dependency
closure from the configured server artifact service. It does not contain the
imported Windows provider assembly.

The imported Windows projects compile the relocated compatibility providers with
explicit source references. Those projects preserve the migration foundation;
their monolithic installer is not the thin-client release. Inventory has a separate
native host. Other providers still need extraction and acceptance as downloadable
hosts before they can be offered as endpoint releases.

Shared device identity, protected storage, transport, signatures, planning and
lifecycle infrastructure remain in `native/` and `packages/`. Shared infrastructure
must not import optional feature implementations. The native check verifies the
bootstrap dependency list independently from feature module checks.

Company-private modules are ignored and excluded from workspace discovery, builds,
Docker contexts and public source exports. Public Git history must start from the
reviewed source export; it must never inherit the private repository history.
