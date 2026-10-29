import { useRef, useState } from "react";
import { type ScopedApi, useScopedModule } from "../../../apps/console/src/use-scoped-module.js";
import "../../desktop-policies/console/desktop.css";

type Entry = {
  manifest: {
    id: string;
    version: string;
    kind: string;
    permissions: string[];
    dependencies: Record<string, string>;
    artifacts: Record<string, unknown>;
  };
};
type Selection = {
  platform: string;
  enabled: Record<string, string>;
  disabled: string[];
  allowed_permissions: string[];
  bootstrap_version: string;
};
type Status = {
  version: string;
  catalog: null | {
    publicationId: string;
    revision: string;
    digest: string;
    expiresAt: string;
    entries: Entry[];
  };
  selections: Selection[];
};
const platforms = ["win-x64", "win-arm64", "osx-x64", "osx-arm64", "linux-x64", "linux-arm64"];
export function NativeModulesPanel({
  api,
  isCurrent,
  canEdit,
}: {
  api: ScopedApi;
  isCurrent: () => boolean;
  canEdit: boolean;
}) {
  const module = useScopedModule<Status>(
    api,
    isCurrent,
    "native-distribution",
    "native.distribute",
    "native-modules",
  );
  const [platform, setPlatform] = useState("win-x64");
  const [draft, setDraft] = useState<Selection | null>(null);
  const [catalogFile, setCatalogFile] = useState<File | null>(null);
  const [notice, setNotice] = useState("");
  const publication = useRef<null | {
    scopeId: string;
    body: { requestId: string; expectedVersion: string; entries: unknown[]; attestations: string[] };
  }>(null);
  const [pendingPublication, setPendingPublication] = useState(false);
  const selection = draft ??
    module.data?.selections.find((value) => value.platform === platform) ?? {
      platform,
      enabled: {},
      disabled: [],
      allowed_permissions: [],
      bootstrap_version: "0.1.0",
    };
  const available = module.data?.catalog?.entries.filter((entry) => entry.manifest.artifacts[platform]) ?? [];
  const features = [
    ...new Set(
      available.filter((entry) => entry.manifest.kind === "feature").map((entry) => entry.manifest.id),
    ),
  ];
  const permissions = [...new Set(available.flatMap((entry) => entry.manifest.permissions))].sort();
  const packages = [...new Set(available.map((entry) => entry.manifest.id))].sort();
  const update = (value: Partial<Selection>) => setDraft({ ...selection, ...value });
  return (
    <section className="panel desktop-panel">
      <div className="panel-heading">
        <h2>Native modules</h2>
        <button type="button" disabled={module.busy || !module.scopeId} onClick={() => void module.load()}>
          Refresh
        </button>
      </div>
      <p>
        Choose the features each platform downloads. Shared dependencies are included in the resolved plan.
      </p>
      <label>
        Management scope
        <select
          value={module.scopeId}
          disabled={module.busy || pendingPublication}
          onChange={(event) => {
            setDraft(null);
            setNotice("");
            module.select(event.target.value);
          }}
        >
          <option value="">Select scope</option>
          {module.scopes.map((scope) => (
            <option key={scope.id} value={scope.id}>
              {scope.name}
            </option>
          ))}
        </select>
      </label>
      {module.error && <p role="alert">{module.error}</p>}
      {notice && <p role="status">{notice}</p>}
      {module.settings && !module.data && canEdit && (
        <button type="button" disabled={module.busy} onClick={() => void module.enable(true)}>
          Enable native distribution
        </button>
      )}
      {module.data && (
        <>
          <div className="panel-heading">
            <h3>Published catalog</h3>
            {canEdit && (
              <button type="button" disabled={module.busy} onClick={() => void module.enable(false)}>
                Disable distribution
              </button>
            )}
          </div>
          {module.data.catalog ? (
            <p>
              Revision {module.data.catalog.revision} · expires{" "}
              {new Date(module.data.catalog.expiresAt).toLocaleString()} ·{" "}
              {module.data.catalog.entries.length} packages
            </p>
          ) : (
            <p>No catalog published.</p>
          )}
          {canEdit && (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                void module.action(async () => {
                  if (!publication.current) {
                    if (!catalogFile || !module.data) return;
                    const bundle = JSON.parse(await catalogFile.text()) as {
                      entries: unknown[];
                      attestations: string[];
                    };
                    publication.current = {
                      scopeId: module.scopeId,
                      body: {
                        requestId: crypto.randomUUID(),
                        expectedVersion: module.data.version,
                        entries: bundle.entries,
                        attestations: bundle.attestations,
                      },
                    };
                    setPendingPublication(true);
                  }
                  const attempt = publication.current;
                  await api(`/v1/scopes/${attempt.scopeId}/native-modules/catalog`, attempt.body, "POST");
                  publication.current = null;
                  if (!isCurrent()) return;
                  setPendingPublication(false);
                  await module.load(attempt.scopeId);
                  setDraft(null);
                  setNotice(
                    "Catalog published. Select a platform and save its module selection to use this revision.",
                  );
                });
              }}
            >
              <label>
                Catalog bundle
                <input
                  type="file"
                  accept="application/json,.json"
                  disabled={module.busy || pendingPublication}
                  onChange={(event) => setCatalogFile(event.target.files?.[0] ?? null)}
                />
              </label>
              <p>The bundle contains package entries and their signed publisher attestations.</p>
              {pendingPublication && (
                <p role="status">
                  Publication {publication.current?.body.requestId} has not been acknowledged. Resolve this
                  same attempt before publishing another catalog. Refresh shows the current published
                  revision.
                </p>
              )}
              <button type="submit" disabled={module.busy || (!catalogFile && !pendingPublication)}>
                {pendingPublication ? "Resolve publication" : "Publish catalog"}
              </button>
              {pendingPublication && (
                <button
                  type="button"
                  disabled={module.busy}
                  onClick={() => {
                    publication.current = null;
                    setPendingPublication(false);
                    setNotice(
                      "Publication draft cleared locally. This does not cancel any server publication; refresh its state before submitting another.",
                    );
                  }}
                >
                  Clear local draft
                </button>
              )}
            </form>
          )}
          {module.data.catalog && (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                void module.action(async () => {
                  const result = await module.mutate<{ plan: { packages: unknown[] } }>(
                    "/native-modules/selection",
                    {
                      platform,
                      catalogId: module.data!.catalog!.publicationId,
                      enabled: selection.enabled,
                      disabled: selection.disabled,
                      allowedPermissions: selection.allowed_permissions,
                      bootstrapVersion: selection.bootstrap_version,
                    },
                  );
                  setDraft(null);
                  setNotice(
                    `Selection saved with ${result?.plan.packages.length ?? 0} packages, including shared dependencies.`,
                  );
                });
              }}
            >
              <h3>Platform selection</h3>
              <label>
                Platform
                <select
                  value={platform}
                  disabled={module.busy}
                  onChange={(event) => {
                    setPlatform(event.target.value);
                    setDraft(null);
                  }}
                >
                  {platforms.map((value) => (
                    <option key={value}>{value}</option>
                  ))}
                </select>
              </label>
              <label>
                Installed bootstrap version
                <input
                  value={selection.bootstrap_version}
                  disabled={!canEdit || module.busy}
                  onChange={(event) => update({ bootstrap_version: event.target.value })}
                />
              </label>
              <table>
                <thead>
                  <tr>
                    <th>Module</th>
                    <th>Selected version</th>
                    <th>Block as dependency</th>
                  </tr>
                </thead>
                <tbody>
                  {packages.map((id) => (
                    <tr key={id}>
                      <td>{id}</td>
                      <td>
                        {features.includes(id) ? (
                          <select
                            aria-label={`${id} version`}
                            disabled={!canEdit || module.busy}
                            value={selection.enabled[id] ?? ""}
                            onChange={(event) => {
                              const enabled = { ...selection.enabled };
                              if (event.target.value) enabled[id] = event.target.value;
                              else delete enabled[id];
                              update({
                                enabled,
                                disabled: selection.disabled.filter((value) => value !== id),
                              });
                            }}
                          >
                            <option value="">Not selected</option>
                            {available
                              .filter((entry) => entry.manifest.id === id)
                              .map((entry) => (
                                <option key={entry.manifest.version}>{entry.manifest.version}</option>
                              ))}
                          </select>
                        ) : (
                          "Shared dependency (automatic)"
                        )}
                      </td>
                      <td>
                        <input
                          aria-label={`Block ${id}`}
                          type="checkbox"
                          disabled={!canEdit || module.busy}
                          checked={selection.disabled.includes(id)}
                          onChange={(event) => {
                            const enabled = { ...selection.enabled };
                            if (event.target.checked) delete enabled[id];
                            update({
                              enabled,
                              disabled: event.target.checked
                                ? [...selection.disabled, id]
                                : selection.disabled.filter((value) => value !== id),
                            });
                          }}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!features.length && <p>This catalog has no features for the selected platform.</p>}
              <h3>Module permissions</h3>
              {permissions.map((permission) => (
                <label key={permission}>
                  <input
                    type="checkbox"
                    disabled={!canEdit || module.busy}
                    checked={selection.allowed_permissions.includes(permission)}
                    onChange={(event) =>
                      update({
                        allowed_permissions: event.target.checked
                          ? [...selection.allowed_permissions, permission]
                          : selection.allowed_permissions.filter((value) => value !== permission),
                      })
                    }
                  />
                  {permission}
                  {!module.settings?.permissionCeiling.includes(permission) && " — unavailable in this scope"}
                </label>
              ))}
              <p>Saving takes effect when an enrolled device next requests configuration.</p>
              {canEdit && (
                <button type="submit" disabled={module.busy}>
                  Save selection
                </button>
              )}
            </form>
          )}
        </>
      )}
    </section>
  );
}
