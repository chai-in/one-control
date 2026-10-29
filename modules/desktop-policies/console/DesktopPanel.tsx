import { useEffect, useRef, useState } from "react";
import "./desktop.css";

type Api = <T>(path: string, body?: unknown, method?: string) => Promise<T>;
type Scope = { id: string; name: string; kind: string; version: string };
type ModuleScope = Scope & {
  permissionCeiling: string[];
  selectedRoots: string[];
  modules: { module_id: string; state: string }[];
};
type PolicyDocument = {
  displayName: string;
  apps: { enabled: boolean; mode: "allowlist" | "denylist"; allow: string[]; deny: string[] };
  web: { enabled: boolean; blockedCategories: string[]; blockedDomains: string[] };
  hardening: {
    bitlocker: {
      mode: "unmanaged" | "protected" | "suspended" | "decrypted";
      backupRecoveryKey: boolean;
      rotateRecoveryKeyDays: number;
      encryptionMethod: "xts_aes_128" | "xts_aes_256";
      encryptUsedSpaceOnly: boolean;
    };
    usbStorage: "unmanaged" | "allowed" | "blocked";
    windowsUpdate: "unmanaged" | "managed";
  };
  monitoring: {
    foregroundTracking: boolean;
    inventory: boolean;
    screenshots: boolean;
    screenshotIntervalSec: number;
    idleThresholdSec: number;
    perAppExclusions: string[];
    notice: string;
    retentionDays: number | null;
  };
};
type Policy = { id: string; version: string; document: PolicyDocument };
type Group = { id: string; name: string; policy_id: string | null };
type Desktop = {
  version: string;
  defaultPolicyId: string | null;
  templates: { id: string; document: PolicyDocument }[];
  policies: Policy[];
  groups: Group[];
  devices: {
    device_id: string;
    hostname: string;
    group_id: string | null;
    policy_id: string | null;
    effective: { policyId: string | null; source: string };
  }[];
  canaries: { id: string; policy_id: string; state: string; targets: number; observed: number }[];
};
type Revision = { version: string; document: PolicyDocument; reason: string; created_at: string };
const lines = (value: string) =>
  value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
function ListField({
  label,
  values,
  change,
}: {
  label: string;
  values: string[];
  change: (items: string[]) => void;
}) {
  const [text, setText] = useState(values.join("\n"));
  useEffect(() => setText(values.join("\n")), [values]);
  return (
    <label>
      {label}
      <textarea
        value={text}
        onChange={(event) => setText(event.target.value)}
        onBlur={() => change(lines(text))}
      />
    </label>
  );
}

export function DesktopPanel({
  api,
  isCurrent,
  canEdit,
}: {
  api: Api;
  isCurrent: () => boolean;
  canEdit: boolean;
}) {
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [scopeId, setScopeId] = useState("");
  const [scope, setScope] = useState<ModuleScope | null>(null);
  const [data, setData] = useState<Desktop | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [scopeName, setScopeName] = useState("");
  const [scopeKind, setScopeKind] = useState("company");
  const [policyKey, setPolicyKey] = useState("");
  const [document, setDocument] = useState<PolicyDocument | null>(null);
  const [confirmReduction, setConfirmReduction] = useState(false);
  const [history, setHistory] = useState<Revision[]>([]);
  const [group, setGroup] = useState({ id: "", name: "", policyId: "" });
  const [targets, setTargets] = useState<string[]>([]);
  const [assignedPolicy, setAssignedPolicy] = useState("unchanged");
  const [assignedGroup, setAssignedGroup] = useState("unchanged");
  const [effective, setEffective] = useState<{
    policyId: string | null;
    source: string;
    disabledModules?: string[];
  } | null>(null);
  const sequence = useRef(0);
  const selection = useRef(scopeId);
  selection.current = scopeId;
  useEffect(() => {
    let live = true;
    api<{ scopes: Scope[] }>("/v1/scopes")
      .then((result) => {
        if (live && isCurrent()) setScopes(result.scopes);
      })
      .catch((failure) => {
        if (live && isCurrent()) setError(String(failure.message));
      });
    return () => {
      live = false;
      sequence.current++;
    };
  }, [api, isCurrent]);
  async function load(id: string) {
    const request = ++sequence.current;
    const current = () => isCurrent() && request === sequence.current && selection.current === id;
    setBusy(true);
    setError("");
    setData(null);
    setScope(null);
    try {
      const result = await api<ModuleScope>(`/v1/scopes/${id}/modules`);
      if (!current()) return;
      setScope(result);
      if (
        result.modules.some((module) => module.module_id === "desktop-policies" && module.state === "enabled")
      ) {
        const desktop = await api<Desktop>(`/v1/scopes/${id}/desktop`);
        if (current()) setData(desktop);
      }
    } catch (failure) {
      if (current()) setError((failure as Error).message);
    } finally {
      if (current()) setBusy(false);
    }
  }
  async function action(work: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await work();
    } catch (failure) {
      if (isCurrent()) setError((failure as Error).message);
    } finally {
      if (isCurrent()) setBusy(false);
    }
  }
  const base = `/v1/scopes/${scopeId}/desktop`;
  async function mutate(path: string, body: object, method = "POST") {
    if (!data) return;
    const selected = scopeId;
    await api(`${base}${path}`, { ...body, expectedVersion: data.version }, method);
    if (isCurrent() && selection.current === selected) {
      setHistory([]);
      await load(selected);
    }
  }
  function choosePolicy(policy: { id: string; document: PolicyDocument }, template = false) {
    setPolicyKey(template ? "" : policy.id);
    setDocument(structuredClone(policy.document));
    setHistory([]);
    setConfirmReduction(false);
  }
  const confirmation = {
    confirmBitlockerDecryption: confirmReduction,
    confirmBitlockerSuspension: confirmReduction,
  };
  return (
    <section className="panel desktop-panel">
      <div className="panel-heading">
        <h2>Desktop policies</h2>
        <button type="button" disabled={!scopeId || busy} onClick={() => void load(scopeId)}>
          Refresh
        </button>
      </div>
      <p>
        Manage policy libraries, groups and rollout candidates within a management scope. Endpoint application
        and verified canary health are not connected yet.
      </p>
      {error && (
        <p role="alert" className="error">
          {error} Refresh current state before retrying a change.
        </p>
      )}
      <label>
        Management scope
        <select
          value={scopeId}
          disabled={busy}
          onChange={(event) => {
            const id = event.target.value;
            selection.current = id;
            setScopeId(id);
            setDocument(null);
            setTargets([]);
            setHistory([]);
            setEffective(null);
            setGroup({ id: "", name: "", policyId: "" });
            setAssignedPolicy("unchanged");
            setAssignedGroup("unchanged");
            setData(null);
            setScope(null);
            if (id) void load(id);
          }}
        >
          <option value="">Select a scope</option>
          {scopes.map((item) => (
            <option key={item.id} value={item.id}>
              {item.name} · {item.kind}
            </option>
          ))}
        </select>
      </label>
      {canEdit && (
        <details>
          <summary>Create management scope</summary>
          <div className="desktop-row">
            <label>
              Name
              <input value={scopeName} onChange={(event) => setScopeName(event.target.value)} />
            </label>
            <label>
              Ownership
              <select value={scopeKind} onChange={(event) => setScopeKind(event.target.value)}>
                <option value="company">Company</option>
                <option value="personal">Personal</option>
              </select>
            </label>
            <button
              type="button"
              disabled={busy || !scopeName.trim()}
              onClick={() =>
                void action(async () => {
                  await api("/v1/scopes", { id: crypto.randomUUID(), name: scopeName, kind: scopeKind });
                  const result = await api<{ scopes: Scope[] }>("/v1/scopes");
                  if (isCurrent()) {
                    setScopes(result.scopes);
                    setScopeName("");
                  }
                })
              }
            >
              Create scope
            </button>
          </div>
        </details>
      )}
      {scope && !data && !busy && (
        <div>
          <p>Desktop policy management is disabled for this scope.</p>
          {canEdit && (
            <button
              type="button"
              onClick={() =>
                void action(async () => {
                  let expectedVersion = scope.version;
                  if (!scope.permissionCeiling.includes("desktop.policy")) {
                    const updated = await api<{ version: string }>(
                      `/v1/scopes/${scopeId}/permissions`,
                      { expectedVersion, permissions: [...scope.permissionCeiling, "desktop.policy"] },
                      "PUT",
                    );
                    expectedVersion = updated.version;
                  }
                  await api(
                    `/v1/scopes/${scopeId}/server-modules`,
                    {
                      expectedVersion,
                      enabled: [
                        ...scope.selectedRoots.filter((id) => id !== "desktop-policies"),
                        "desktop-policies",
                      ],
                    },
                    "PUT",
                  );
                  if (isCurrent()) await load(scopeId);
                })
              }
            >
              Enable desktop policy management
            </button>
          )}
        </div>
      )}
      {data && (
        <>
          <div className="desktop-row">
            <label>
              Policy library
              <select
                value={policyKey}
                onChange={(event) => {
                  const policy = data.policies.find((item) => item.id === event.target.value);
                  if (policy) choosePolicy(policy);
                }}
              >
                <option value="">Select a policy</option>
                {data.policies.map((policy) => (
                  <option key={policy.id} value={policy.id}>
                    {policy.document.displayName} · v{policy.version}
                  </option>
                ))}
              </select>
            </label>
            {canEdit &&
              data.templates.map((template) => (
                <button
                  type="button"
                  key={template.id}
                  disabled={busy}
                  onClick={() => choosePolicy(template, true)}
                >
                  New from {template.document.displayName}
                </button>
              ))}
          </div>
          <label>
            Fleet default
            <select
              disabled={!canEdit || busy}
              value={data.defaultPolicyId ?? ""}
              onChange={(event) =>
                void action(() => mutate("/default-policy", { policyId: event.target.value || null }, "PUT"))
              }
            >
              <option value="">No default policy</option>
              {data.policies.map((policy) => (
                <option key={policy.id} value={policy.id}>
                  {policy.document.displayName}
                </option>
              ))}
            </select>
          </label>
          {document && (
            <fieldset disabled={!canEdit || busy}>
              <legend>{document.displayName}</legend>
              <div className="desktop-row">
                <label>
                  Policy ID
                  <input
                    value={policyKey}
                    pattern="[a-z0-9][a-z0-9-]{1,62}"
                    onChange={(event) => setPolicyKey(event.target.value)}
                  />
                </label>
                <label>
                  Display name
                  <input
                    value={document.displayName}
                    onChange={(event) => setDocument({ ...document, displayName: event.target.value })}
                  />
                </label>
              </div>
              <details>
                <summary>Application control</summary>
                <label className="desktop-check">
                  <input
                    type="checkbox"
                    checked={document.apps.enabled}
                    onChange={(event) =>
                      setDocument({ ...document, apps: { ...document.apps, enabled: event.target.checked } })
                    }
                  />
                  Request application control
                </label>
                <label>
                  Mode
                  <select
                    value={document.apps.mode}
                    onChange={(event) =>
                      setDocument({
                        ...document,
                        apps: {
                          ...document.apps,
                          mode: event.target.value as PolicyDocument["apps"]["mode"],
                        },
                      })
                    }
                  >
                    <option value="denylist">Block listed applications</option>
                    <option value="allowlist">Allow only listed applications</option>
                  </select>
                </label>
                {(["allow", "deny"] as const).map((key) => (
                  <ListField
                    key={key}
                    label={key === "allow" ? "Allowed process names" : "Blocked process names"}
                    values={document.apps[key]}
                    change={(items) => setDocument({ ...document, apps: { ...document.apps, [key]: items } })}
                  />
                ))}
              </details>
              <details>
                <summary>Web filtering</summary>
                <label className="desktop-check">
                  <input
                    type="checkbox"
                    checked={document.web.enabled}
                    onChange={(event) =>
                      setDocument({ ...document, web: { ...document.web, enabled: event.target.checked } })
                    }
                  />
                  Request web filtering
                </label>
                <div className="desktop-row">
                  {[
                    "adult",
                    "gambling",
                    "social-media",
                    "streaming",
                    "gaming",
                    "malware",
                    "phishing",
                    "cryptomining",
                    "proxy-vpn",
                    "file-sharing",
                  ].map((category) => (
                    <label className="desktop-check" key={category}>
                      <input
                        type="checkbox"
                        checked={document.web.blockedCategories.includes(category)}
                        onChange={(event) =>
                          setDocument({
                            ...document,
                            web: {
                              ...document.web,
                              blockedCategories: event.target.checked
                                ? [...document.web.blockedCategories, category]
                                : document.web.blockedCategories.filter((item) => item !== category),
                            },
                          })
                        }
                      />
                      {category}
                    </label>
                  ))}
                </div>
                <ListField
                  label="Blocked domains"
                  values={document.web.blockedDomains}
                  change={(items) =>
                    setDocument({ ...document, web: { ...document.web, blockedDomains: items } })
                  }
                />
              </details>
              <details>
                <summary>BitLocker and device hardening</summary>
                <div className="desktop-row">
                  <label>
                    BitLocker
                    <select
                      value={document.hardening.bitlocker.mode}
                      onChange={(event) => {
                        setConfirmReduction(false);
                        setDocument({
                          ...document,
                          hardening: {
                            ...document.hardening,
                            bitlocker: {
                              ...document.hardening.bitlocker,
                              mode: event.target.value as PolicyDocument["hardening"]["bitlocker"]["mode"],
                            },
                          },
                        });
                      }}
                    >
                      {["unmanaged", "protected", "suspended", "decrypted"].map((value) => (
                        <option key={value}>{value}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Encryption
                    <select
                      value={document.hardening.bitlocker.encryptionMethod}
                      onChange={(event) =>
                        setDocument({
                          ...document,
                          hardening: {
                            ...document.hardening,
                            bitlocker: {
                              ...document.hardening.bitlocker,
                              encryptionMethod: event.target.value as "xts_aes_128" | "xts_aes_256",
                            },
                          },
                        })
                      }
                    >
                      <option value="xts_aes_256">XTS AES 256</option>
                      <option value="xts_aes_128">XTS AES 128</option>
                    </select>
                  </label>
                  <label>
                    Recovery key rotation days (0 disables)
                    <input
                      type="number"
                      min="0"
                      max="365"
                      value={document.hardening.bitlocker.rotateRecoveryKeyDays}
                      onChange={(event) =>
                        setDocument({
                          ...document,
                          hardening: {
                            ...document.hardening,
                            bitlocker: {
                              ...document.hardening.bitlocker,
                              rotateRecoveryKeyDays: Number(event.target.value),
                            },
                          },
                        })
                      }
                    />
                  </label>
                </div>
                {(["backupRecoveryKey", "encryptUsedSpaceOnly"] as const).map((key) => (
                  <label className="desktop-check" key={key}>
                    <input
                      type="checkbox"
                      checked={document.hardening.bitlocker[key]}
                      onChange={(event) =>
                        setDocument({
                          ...document,
                          hardening: {
                            ...document.hardening,
                            bitlocker: { ...document.hardening.bitlocker, [key]: event.target.checked },
                          },
                        })
                      }
                    />
                    {key === "backupRecoveryKey" ? "Escrow recovery key" : "Encrypt used space only"}
                  </label>
                ))}
                <label>
                  USB storage
                  <select
                    value={document.hardening.usbStorage}
                    onChange={(event) =>
                      setDocument({
                        ...document,
                        hardening: {
                          ...document.hardening,
                          usbStorage: event.target.value as PolicyDocument["hardening"]["usbStorage"],
                        },
                      })
                    }
                  >
                    {["unmanaged", "allowed", "blocked"].map((value) => (
                      <option key={value}>{value}</option>
                    ))}
                  </select>
                </label>
                <label>
                  Windows updates
                  <select
                    value={document.hardening.windowsUpdate}
                    onChange={(event) =>
                      setDocument({
                        ...document,
                        hardening: {
                          ...document.hardening,
                          windowsUpdate: event.target.value as "unmanaged" | "managed",
                        },
                      })
                    }
                  >
                    <option value="unmanaged">Unmanaged</option>
                    <option value="managed">Managed</option>
                  </select>
                </label>
              </details>
              <details>
                <summary>Optional monitoring</summary>
                {(["foregroundTracking", "inventory", "screenshots"] as const).map((key) => (
                  <label className="desktop-check" key={key}>
                    <input
                      type="checkbox"
                      checked={document.monitoring[key]}
                      onChange={(event) =>
                        setDocument({
                          ...document,
                          monitoring: { ...document.monitoring, [key]: event.target.checked },
                        })
                      }
                    />
                    {
                      {
                        foregroundTracking: "Application activity",
                        inventory: "Inventory",
                        screenshots: "Screenshots",
                      }[key]
                    }
                  </label>
                ))}
                <label>
                  User notice
                  <textarea
                    value={document.monitoring.notice}
                    onChange={(event) =>
                      setDocument({
                        ...document,
                        monitoring: { ...document.monitoring, notice: event.target.value },
                      })
                    }
                  />
                </label>
                <ListField
                  label="Apps excluded from capture"
                  values={document.monitoring.perAppExclusions}
                  change={(items) =>
                    setDocument({
                      ...document,
                      monitoring: { ...document.monitoring, perAppExclusions: items },
                    })
                  }
                />
                <div className="desktop-row">
                  {(["screenshotIntervalSec", "idleThresholdSec", "retentionDays"] as const).map((key) => (
                    <label key={key}>
                      {
                        {
                          screenshotIntervalSec: "Screenshot interval (seconds)",
                          idleThresholdSec: "Idle threshold (seconds)",
                          retentionDays: "Retention (days)",
                        }[key]
                      }
                      <input
                        type="number"
                        min={key === "retentionDays" ? 1 : 30}
                        max={key === "retentionDays" ? 3650 : 3600}
                        value={document.monitoring[key] ?? ""}
                        onChange={(event) =>
                          setDocument({
                            ...document,
                            monitoring: { ...document.monitoring, [key]: Number(event.target.value) },
                          })
                        }
                      />
                    </label>
                  ))}
                </div>
              </details>
              <label className="desktop-check">
                <input
                  type="checkbox"
                  checked={confirmReduction}
                  onChange={(event) => setConfirmReduction(event.target.checked)}
                />
                Confirm any requested BitLocker suspension or decryption for this save, clone, rollback or
                promotion
              </label>
              <div className="desktop-row">
                <button
                  type="button"
                  disabled={!policyKey}
                  onClick={() =>
                    void action(() =>
                      mutate(
                        `/policies/${encodeURIComponent(policyKey)}`,
                        { document: { ...document, ...confirmation } },
                        "PUT",
                      ),
                    )
                  }
                >
                  Save policy
                </button>
                <button
                  type="button"
                  disabled={!data.policies.some((policy) => policy.id === policyKey)}
                  onClick={() =>
                    void action(async () => {
                      const result = await api<{ versions: Revision[] }>(
                        `${base}/policies/${policyKey}/versions`,
                      );
                      if (isCurrent()) setHistory(result.versions);
                    })
                  }
                >
                  Version history
                </button>
                <button
                  type="button"
                  disabled={!data.policies.some((policy) => policy.id === policyKey)}
                  onClick={() =>
                    void action(async () => {
                      await mutate(`/policies/${policyKey}/clone`, {
                        id: `${policyKey.slice(0, 45)}-${crypto.randomUUID().slice(0, 8)}`,
                        displayName: `${document.displayName.slice(0, 110)} copy`,
                        ...confirmation,
                      });
                    })
                  }
                >
                  Clone saved policy
                </button>
                <button
                  type="button"
                  disabled={!data.policies.some((policy) => policy.id === policyKey)}
                  onClick={() =>
                    void action(async () => {
                      await mutate(`/policies/${policyKey}`, {}, "DELETE");
                      if (isCurrent()) setDocument(null);
                    })
                  }
                >
                  Delete unused policy
                </button>
              </div>
              {history.map((revision) => (
                <div className="desktop-row" key={revision.version}>
                  <span>
                    v{revision.version} · {revision.reason} · {new Date(revision.created_at).toLocaleString()}
                  </span>
                  <button
                    type="button"
                    onClick={() =>
                      void action(() =>
                        mutate(`/policies/${policyKey}/rollback`, {
                          version: revision.version,
                          ...confirmation,
                        }),
                      )
                    }
                  >
                    Restore as new version
                  </button>
                  <details>
                    <summary>View revision</summary>
                    <pre>{JSON.stringify(revision.document, null, 2)}</pre>
                  </details>
                </div>
              ))}
            </fieldset>
          )}
          <h3>Groups</h3>
          <div className="desktop-row">
            {data.groups.map((item) => (
              <button
                type="button"
                key={item.id}
                disabled={busy}
                onClick={() => setGroup({ id: item.id, name: item.name, policyId: item.policy_id ?? "" })}
              >
                {item.name}
              </button>
            ))}
          </div>
          {canEdit && (
            <fieldset disabled={busy}>
              <legend>{group.id ? "Edit group" : "New group"}</legend>
              <div className="desktop-row">
                <label>
                  Name
                  <input
                    value={group.name}
                    onChange={(event) => setGroup({ ...group, name: event.target.value })}
                  />
                </label>
                <label>
                  Group policy
                  <select
                    value={group.policyId}
                    onChange={(event) => setGroup({ ...group, policyId: event.target.value })}
                  >
                    <option value="">Inherit fleet default</option>
                    {data.policies.map((policy) => (
                      <option key={policy.id} value={policy.id}>
                        {policy.document.displayName}
                      </option>
                    ))}
                  </select>
                </label>
                <button
                  type="button"
                  disabled={!group.name}
                  onClick={() =>
                    void action(() =>
                      mutate(
                        `/groups/${group.id || crypto.randomUUID()}`,
                        { name: group.name, policyId: group.policyId || null },
                        "PUT",
                      ),
                    )
                  }
                >
                  Save group
                </button>
                <button type="button" onClick={() => setGroup({ id: "", name: "", policyId: "" })}>
                  New group
                </button>
                {group.id && (
                  <button
                    type="button"
                    onClick={() =>
                      void action(async () => {
                        await mutate(`/groups/${group.id}`, {}, "DELETE");
                        if (isCurrent()) setGroup({ id: "", name: "", policyId: "" });
                      })
                    }
                  >
                    Delete group
                  </button>
                )}
              </div>
            </fieldset>
          )}
          <h3>Device assignments</h3>
          <p>
            Device overrides take precedence over group policy, then fleet default. Changing assignments or
            group policies aborts staged canaries for this scope.
          </p>
          {data.devices.length === 0 && <p>No active native enrollments in this scope.</p>}
          {data.devices.map((device) => (
            <div className="desktop-row" key={device.device_id}>
              <label className="desktop-check">
                <input
                  type="checkbox"
                  disabled={!canEdit || busy}
                  checked={targets.includes(device.device_id)}
                  onChange={(event) =>
                    setTargets(
                      event.target.checked
                        ? [...targets, device.device_id]
                        : targets.filter((id) => id !== device.device_id),
                    )
                  }
                />
                {device.hostname}
              </label>
              <span>
                {device.effective.policyId ?? "No policy"} · {device.effective.source}
              </span>
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  void action(async () => {
                    const result = await api<NonNullable<typeof effective>>(
                      `${base}/devices/${device.device_id}/policy`,
                    );
                    if (isCurrent()) setEffective(result);
                  })
                }
              >
                Effective policy
              </button>
            </div>
          ))}
          {effective && (
            <p>
              Effective policy: {effective.policyId ?? "none"} from {effective.source}. Disabled requested
              modules: {effective.disabledModules?.join(", ") || "none"}. Endpoint execution is not connected.
            </p>
          )}
          {canEdit && (
            <fieldset disabled={busy || !targets.length}>
              <legend>Selected devices ({targets.length})</legend>
              <div className="desktop-row">
                <label>
                  Group
                  <select value={assignedGroup} onChange={(event) => setAssignedGroup(event.target.value)}>
                    <option value="unchanged">Leave unchanged</option>
                    <option value="">Remove group</option>
                    {data.groups.map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Policy override
                  <select value={assignedPolicy} onChange={(event) => setAssignedPolicy(event.target.value)}>
                    <option value="unchanged">Leave unchanged</option>
                    <option value="">Inherit group or default</option>
                    {data.policies.map((policy) => (
                      <option key={policy.id} value={policy.id}>
                        {policy.document.displayName}
                      </option>
                    ))}
                  </select>
                </label>
                <button
                  type="button"
                  disabled={assignedPolicy === "unchanged" && assignedGroup === "unchanged"}
                  onClick={() =>
                    void action(() =>
                      mutate(
                        "/assignments",
                        {
                          deviceIds: targets,
                          ...(assignedGroup !== "unchanged" ? { groupId: assignedGroup || null } : {}),
                          ...(assignedPolicy !== "unchanged" ? { policyId: assignedPolicy || null } : {}),
                        },
                        "PUT",
                      ),
                    )
                  }
                >
                  Assign
                </button>
                <button
                  type="button"
                  disabled={!document || !data.policies.some((policy) => policy.id === policyKey)}
                  onClick={() =>
                    void action(() =>
                      mutate(`/policies/${policyKey}/canaries`, {
                        document: { ...document, ...confirmation },
                        deviceIds: targets,
                      }),
                    )
                  }
                >
                  Stage editor policy for selected devices
                </button>
              </div>
            </fieldset>
          )}
          <h3>Policy canaries</h3>
          {data.canaries.map((canary) => (
            <div className="desktop-row" key={canary.id}>
              <span>
                {canary.policy_id} · {canary.state} · {canary.observed}/{canary.targets} verified reports
              </span>
              {["pending", "healthy"].includes(canary.state) && canEdit && (
                <>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void action(() => mutate(`/canaries/${canary.id}/abort`, {}))}
                  >
                    Abort
                  </button>
                  <button
                    type="button"
                    disabled={busy || canary.observed !== canary.targets}
                    onClick={() => void action(() => mutate(`/canaries/${canary.id}/promote`, confirmation))}
                  >
                    Promote
                  </button>
                </>
              )}
            </div>
          ))}
        </>
      )}
    </section>
  );
}
