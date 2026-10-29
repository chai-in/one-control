import { useState } from "react";
import { type ScopedApi, useScopedModule } from "../../../apps/console/src/use-scoped-module.js";
import "../../desktop-policies/console/desktop.css";

type Person = {
  id: string;
  name: string;
  email: string | null;
  department: string | null;
  employee_code: string | null;
  title: string | null;
  location: string | null;
  identity_issuer: string | null;
  identity_subject: string | null;
  state: string;
  asset_count: number;
};
type Asset = {
  id: string;
  kind: string;
  identifier: string;
  identifier_type: string;
  label: string;
  employee_id: string | null;
  employee_name: string | null;
  employee_state: string | null;
  notes: string;
  state: string;
};
type Inventory = {
  version: string;
  kind: string;
  people: Person[];
  assets: Asset[];
  links: {
    asset_id: string;
    source: string;
    source_ref: string;
    verification: string;
    native_active: boolean | null;
  }[];
  devices: {
    enrollment_id: string;
    device_id: string;
    hostname: string;
    platform: string;
    asset_id: string | null;
  }[];
};
const newPerson = () => ({
  id: "",
  name: "",
  email: "",
  department: "",
  employeeCode: "",
  title: "",
  location: "",
  identityIssuer: "",
  identitySubject: "",
  state: "active",
});
const newAsset = () => ({
  id: "",
  kind: "windows",
  identifier: "",
  identifierType: "asset-tag",
  label: "",
  employeeId: "",
  notes: "",
  state: "stock",
});
const optional = (value: string) => value.trim() || null;
export function AssetsPanel({
  api,
  isCurrent,
  canEdit,
}: {
  api: ScopedApi;
  isCurrent: () => boolean;
  canEdit: boolean;
}) {
  const module = useScopedModule<Inventory>(api, isCurrent, "asset-management", "assets.manage", "assets");
  const { data, busy, scopeId } = module;
  const [person, setPerson] = useState(newPerson);
  const [asset, setAsset] = useState(newAsset);
  const [search, setSearch] = useState("");
  const [employeeFilter, setEmployeeFilter] = useState("");
  const [link, setLink] = useState({ source: "native", reference: "" });
  const [offboarding, setOffboarding] = useState<{
    assets: { id: string; label: string; state: string }[];
  } | null>(null);
  function editAsset(row: Asset) {
    setAsset({
      id: row.id,
      kind: row.kind,
      identifier: row.identifier,
      identifierType: row.identifier_type,
      label: row.label,
      employeeId: row.employee_id ?? "",
      notes: row.notes,
      state: row.state,
    });
    setLink({ source: "native", reference: "" });
  }
  const visible =
    data?.assets.filter(
      (row) =>
        `${row.label} ${row.identifier} ${row.employee_name ?? ""}`
          .toLowerCase()
          .includes(search.toLowerCase()) &&
        (!employeeFilter ||
          (employeeFilter === "unassigned" ? !row.employee_id : row.employee_id === employeeFilter)),
    ) ?? [];
  return (
    <section className="panel desktop-panel">
      <div className="panel-heading">
        <h2>Assets and people</h2>
        <button type="button" disabled={busy || !scopeId} onClick={() => void module.load()}>
          Refresh
        </button>
      </div>
      <label>
        Management scope
        <select
          disabled={busy}
          value={scopeId}
          onChange={(event) => {
            setPerson(newPerson());
            setAsset(newAsset());
            setOffboarding(null);
            setEmployeeFilter("");
            module.select(event.target.value);
          }}
        >
          <option value="">Select a scope</option>
          {module.scopes.map((scope) => (
            <option key={scope.id} value={scope.id}>
              {scope.name}
            </option>
          ))}
        </select>
      </label>
      {module.error && <p role="alert">{module.error} Refresh current state before retrying a change.</p>}
      {module.settings && !data && !busy && (
        <p>
          Asset management is disabled.{" "}
          {canEdit && (
            <button type="button" onClick={() => void module.enable(true)}>
              Enable asset management
            </button>
          )}
        </p>
      )}
      {data && (
        <>
          {canEdit && (
            <button type="button" disabled={busy} onClick={() => void module.enable(false)}>
              Disable asset management and retain records
            </button>
          )}
          {data.kind === "company" && (
            <>
              <h3>People</h3>
              <div className="desktop-row">
                {data.people.map((row) => (
                  <button
                    type="button"
                    key={row.id}
                    disabled={busy}
                    onClick={() => {
                      setPerson({
                        id: row.id,
                        name: row.name,
                        email: row.email ?? "",
                        department: row.department ?? "",
                        employeeCode: row.employee_code ?? "",
                        title: row.title ?? "",
                        location: row.location ?? "",
                        identityIssuer: row.identity_issuer ?? "",
                        identitySubject: row.identity_subject ?? "",
                        state: row.state,
                      });
                      setEmployeeFilter(row.id);
                    }}
                  >
                    {row.name} · {row.state} · {row.asset_count} assets
                  </button>
                ))}
              </div>
              {canEdit && (
                <fieldset disabled={busy}>
                  <legend>{person.id ? "Edit person" : "New person"}</legend>
                  <div className="desktop-row">
                    {(
                      [
                        "name",
                        "email",
                        "department",
                        "employeeCode",
                        "title",
                        "location",
                        "identityIssuer",
                        "identitySubject",
                      ] as const
                    ).map((key) => (
                      <label key={key}>
                        {
                          {
                            name: "Name",
                            email: "Email",
                            department: "Department",
                            employeeCode: "Employee code",
                            title: "Job title",
                            location: "Location",
                            identityIssuer: "Identity issuer (optional)",
                            identitySubject: "Identity subject (optional)",
                          }[key]
                        }
                        <input
                          type={key === "email" ? "email" : "text"}
                          value={person[key]}
                          onChange={(event) => setPerson({ ...person, [key]: event.target.value })}
                        />
                      </label>
                    ))}
                  </div>
                  <label>
                    Status
                    <select
                      value={person.state}
                      onChange={(event) => setPerson({ ...person, state: event.target.value })}
                    >
                      <option value="active">Active</option>
                      <option value="offboarded">Offboarded</option>
                    </select>
                  </label>
                  <div className="desktop-row">
                    <button
                      type="button"
                      disabled={!person.name.trim()}
                      onClick={() =>
                        void module.action(async () => {
                          const id = person.id || crypto.randomUUID();
                          await module.mutate(`/people/${id}`, {
                            name: person.name,
                            email: optional(person.email),
                            department: optional(person.department),
                            employeeCode: optional(person.employeeCode),
                            title: optional(person.title),
                            location: optional(person.location),
                            identityIssuer: optional(person.identityIssuer),
                            identitySubject: optional(person.identitySubject),
                            state: person.state,
                          });
                          if (isCurrent()) setPerson({ ...person, id });
                        })
                      }
                    >
                      Save person
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setPerson(newPerson());
                        setEmployeeFilter("");
                      }}
                    >
                      New person
                    </button>
                    {person.id && (
                      <button
                        type="button"
                        onClick={() =>
                          void module.action(async () => {
                            const result = await module.mutate<{
                              result: { assets: { id: string; label: string; state: string }[] };
                            }>(`/people/${person.id}/offboard`, {}, "POST");
                            if (isCurrent() && result) {
                              setPerson({ ...person, state: "offboarded" });
                              setOffboarding(result.result);
                            }
                          })
                        }
                      >
                        Record offboarding
                      </button>
                    )}
                  </div>
                  <p>
                    Offboarding records employment status and lists assets for return or reassignment. Device
                    actions and identity-provider access changes are separate operations.
                  </p>
                </fieldset>
              )}
              {offboarding && (
                <div>
                  <h4>Assets requiring follow-up</h4>
                  {offboarding.assets.length ? (
                    offboarding.assets.map((row) => (
                      <p key={row.id}>
                        {row.label} · {row.state}
                      </p>
                    ))
                  ) : (
                    <p>No non-retired assets remain assigned.</p>
                  )}
                </div>
              )}
            </>
          )}
          <h3>Asset register</h3>
          <div className="desktop-row">
            <label>
              Search
              <input value={search} onChange={(event) => setSearch(event.target.value)} />
            </label>
            <label>
              Assignment
              <select value={employeeFilter} onChange={(event) => setEmployeeFilter(event.target.value)}>
                <option value="">All assets</option>
                <option value="unassigned">Unassigned</option>
                {data.people.map((row) => (
                  <option key={row.id} value={row.id}>
                    {row.name}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Asset</th>
                  <th>Identifier</th>
                  <th>Assigned to</th>
                  <th>Status</th>
                  <th>Links</th>
                  <th>Record</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((row) => (
                  <tr key={row.id}>
                    <td>
                      {row.label}
                      <small>{row.kind}</small>
                    </td>
                    <td>{row.identifier}</td>
                    <td>
                      {row.employee_name ?? "Unassigned"}
                      {row.employee_state === "offboarded" ? " · offboarded" : ""}
                    </td>
                    <td>{row.state}</td>
                    <td>
                      {data.links
                        .filter((item) => item.asset_id === row.id)
                        .map(
                          (item) =>
                            `${item.source}: ${item.source === "native" ? (item.native_active ? "live enrollment" : "inactive enrollment") : "operator-recorded"}`,
                        )
                        .join(", ") || "None"}
                    </td>
                    <td>
                      <button type="button" disabled={busy} onClick={() => editAsset(row)}>
                        Open
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {canEdit && (
            <fieldset disabled={busy}>
              <legend>{asset.id ? "Edit asset" : "New asset"}</legend>
              <div className="desktop-row">
                <label>
                  Label
                  <input
                    value={asset.label}
                    onChange={(event) => setAsset({ ...asset, label: event.target.value })}
                  />
                </label>
                <label>
                  Kind
                  <select
                    value={asset.kind}
                    onChange={(event) => setAsset({ ...asset, kind: event.target.value })}
                  >
                    {["windows", "macos", "other"].map((kind) => (
                      <option key={kind}>{kind}</option>
                    ))}
                  </select>
                </label>
                <label>
                  Identifier type
                  <select
                    value={asset.identifierType}
                    onChange={(event) => setAsset({ ...asset, identifierType: event.target.value })}
                  >
                    {["asset-tag", "serial", "hostname", "other"].map((value) => (
                      <option key={value}>{value}</option>
                    ))}
                  </select>
                </label>
                <label>
                  Identifier
                  <input
                    value={asset.identifier}
                    onChange={(event) => setAsset({ ...asset, identifier: event.target.value })}
                  />
                </label>
                <label>
                  Employee
                  <select
                    value={asset.employeeId}
                    onChange={(event) => setAsset({ ...asset, employeeId: event.target.value })}
                  >
                    <option value="">Unassigned</option>
                    {data.people.map((row) => (
                      <option key={row.id} value={row.id}>
                        {row.name} · {row.state}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Status
                  <select
                    value={asset.state}
                    onChange={(event) => setAsset({ ...asset, state: event.target.value })}
                  >
                    {["stock", "assigned", "repair", "lost", "retired"].map((value) => (
                      <option key={value}>{value}</option>
                    ))}
                  </select>
                </label>
              </div>
              <label>
                Notes
                <textarea
                  value={asset.notes}
                  onChange={(event) => setAsset({ ...asset, notes: event.target.value })}
                />
              </label>
              <div className="desktop-row">
                <button
                  type="button"
                  disabled={!asset.label.trim() || !asset.identifier.trim()}
                  onClick={() =>
                    void module.action(async () => {
                      const id = asset.id || crypto.randomUUID();
                      const { id: _id, ...input } = asset;
                      await module.mutate(`/assets/${id}`, {
                        ...input,
                        employeeId: asset.employeeId || null,
                      });
                      if (isCurrent()) setAsset({ ...asset, id });
                    })
                  }
                >
                  Save asset
                </button>
                <button type="button" onClick={() => setAsset(newAsset())}>
                  New asset
                </button>
                {asset.id && (
                  <button
                    type="button"
                    onClick={() =>
                      void module.action(async () => {
                        await module.mutate(`/assets/${asset.id}`, {}, "DELETE");
                        if (isCurrent()) setAsset(newAsset());
                      })
                    }
                  >
                    Delete register entry
                  </button>
                )}
              </div>
              <p>
                Changing the asset identifier or kind clears its source links for explicit reconciliation.
                Deleting a register entry does not uninstall or wipe its computer.
              </p>
            </fieldset>
          )}
          {asset.id && (
            <>
              <h3>Source links for {asset.label}</h3>
              {data.links
                .filter((row) => row.asset_id === asset.id)
                .map((row) => (
                  <div className="desktop-row" key={row.source}>
                    <span>
                      {row.source} · {row.source_ref} · {row.verification}
                      {row.source === "native"
                        ? row.native_active
                          ? " · active"
                          : " · inactive"
                        : " · not verified for command targeting"}
                    </span>
                    {canEdit && (
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() =>
                          void module.action(async () => {
                            await module.mutate(`/assets/${asset.id}/links/${row.source}`, {}, "DELETE");
                          })
                        }
                      >
                        Unlink
                      </button>
                    )}
                  </div>
                ))}
              {canEdit && (
                <fieldset disabled={busy}>
                  <legend>Record a source link</legend>
                  <div className="desktop-row">
                    <label>
                      Source
                      <select
                        value={link.source}
                        onChange={(event) => setLink({ source: event.target.value, reference: "" })}
                      >
                        {["native", "falcon", "ema"].map((source) => (
                          <option key={source}>{source}</option>
                        ))}
                      </select>
                    </label>
                    {link.source === "native" ? (
                      <label>
                        Native enrollment
                        <select
                          value={link.reference}
                          onChange={(event) => setLink({ ...link, reference: event.target.value })}
                        >
                          <option value="">Select a current enrollment</option>
                          {data.devices.map((device) => (
                            <option key={device.enrollment_id} value={device.enrollment_id}>
                              {device.hostname} · {device.platform}
                              {device.asset_id ? " · linked" : " · unlinked"}
                            </option>
                          ))}
                        </select>
                      </label>
                    ) : (
                      <label>
                        {link.source === "falcon" ? "Falcon AID" : "EMA endpoint ID"}
                        <input
                          value={link.reference}
                          onChange={(event) => setLink({ ...link, reference: event.target.value })}
                        />
                      </label>
                    )}
                    <button
                      type="button"
                      disabled={!link.reference}
                      onClick={() =>
                        void module.action(async () => {
                          await module.mutate(`/assets/${asset.id}/links/${link.source}`, {
                            reference: link.reference,
                          });
                        })
                      }
                    >
                      Record link
                    </button>
                  </div>
                </fieldset>
              )}
            </>
          )}
          <h3>Unlinked native devices</h3>
          {data.devices
            .filter((device) => !device.asset_id)
            .map((device) => (
              <p key={device.enrollment_id}>
                {device.hostname} · {device.platform}
              </p>
            ))}
        </>
      )}
    </section>
  );
}
