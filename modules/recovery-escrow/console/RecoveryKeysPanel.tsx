import { useEffect, useRef, useState } from "react";
import { identity } from "../../../apps/console/src/auth.js";
import { type ScopedApi, useScopedModule } from "../../../apps/console/src/use-scoped-module.js";
import "../../desktop-policies/console/desktop.css";

type Key = {
  id: string;
  device_id: string;
  enrollment_id: string;
  hostname: string;
  volume: string;
  protector_id: string;
  escrowed_at: string;
  enrollment_revoked_at: string | null;
};
type Revealed = { id: string; volume: string; protectorId: string; recoveryKey: string };
export function RecoveryKeysPanel({
  api,
  isCurrent,
  canEdit,
}: {
  api: ScopedApi;
  isCurrent: () => boolean;
  canEdit: boolean;
}) {
  const module = useScopedModule<{ version: string; keys: Key[] }>(
    api,
    isCurrent,
    "recovery-escrow",
    "bitlocker.escrow",
    "recovery-keys",
  );
  const [revealed, setRevealed] = useState<Revealed | null>(null),
    [reason, setReason] = useState("device-recovery"),
    [search, setSearch] = useState("");
  const selectedScope = useRef(module.scopeId);
  selectedScope.current = module.scopeId;
  useEffect(() => {
    if (!revealed) return;
    const timer = setTimeout(() => setRevealed(null), 30000);
    const hide = () => {
      if (document.hidden) setRevealed(null);
    };
    document.addEventListener("visibilitychange", hide);
    return () => {
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", hide);
    };
  }, [revealed]);
  const desktopEnabled = module.settings?.modules.some(
    (value) => value.module_id === "desktop-policies" && value.state === "enabled",
  );
  return (
    <section className="panel desktop-panel">
      <div className="panel-heading">
        <h2>Recovery keys</h2>
        <button
          type="button"
          disabled={module.busy || !module.scopeId}
          onClick={() => {
            setRevealed(null);
            void module.load();
          }}
        >
          Refresh
        </button>
      </div>
      <label>
        Management scope
        <select
          value={module.scopeId}
          disabled={module.busy}
          onChange={(event) => {
            setRevealed(null);
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
      {module.settings && !module.data && canEdit && (
        <>
          <p>
            Enable Desktop policies for this scope first. Key backup must also be selected in the assigned
            desktop policy.
          </p>
          <button
            type="button"
            disabled={module.busy || !desktopEnabled}
            onClick={() => void module.enable(true)}
          >
            Enable encrypted recovery-key escrow
          </button>
        </>
      )}
      {module.data && (
        <>
          <p>
            Key values require a separate reveal grant and recent multifactor sign-in. Each reveal is audited.
          </p>
          {canEdit && (
            <div className="panel-heading">
              <button
                type="button"
                disabled={module.busy}
                onClick={() => {
                  setRevealed(null);
                  void module.enable(false);
                }}
              >
                Disable escrow
              </button>
              {identity && (
                <button
                  type="button"
                  onClick={() => {
                    setRevealed(null);
                    void module.action(() =>
                      identity!.signinRedirect({ prompt: "login", extraQueryParams: { max_age: 0 } }),
                    );
                  }}
                >
                  Verify sign-in
                </button>
              )}
            </div>
          )}
          <label>
            Find computer or protector
            <input value={search} onChange={(event) => setSearch(event.target.value)} />
          </label>
          {canEdit && (
            <label>
              Reason for reveal
              <select value={reason} onChange={(event) => setReason(event.target.value)}>
                <option value="device-recovery">Device recovery</option>
                <option value="key-verification">Key verification</option>
                <option value="incident-response">Incident response</option>
              </select>
            </label>
          )}
          <table>
            <thead>
              <tr>
                <th>Computer</th>
                <th>Volume</th>
                <th>Protector</th>
                <th>Stored</th>
                <th>Enrollment</th>
                <th>Access</th>
              </tr>
            </thead>
            <tbody>
              {module.data.keys
                .filter((key) =>
                  `${key.hostname} ${key.protector_id}`.toLowerCase().includes(search.toLowerCase()),
                )
                .map((key) => (
                  <tr key={key.id}>
                    <td>{key.hostname}</td>
                    <td>{key.volume}</td>
                    <td>{key.protector_id}</td>
                    <td>{new Date(key.escrowed_at).toLocaleString()}</td>
                    <td>{key.enrollment_revoked_at ? "Revoked; historical key" : "Active"}</td>
                    <td>
                      {canEdit && (
                        <button
                          type="button"
                          disabled={module.busy}
                          onClick={() => {
                            setRevealed(null);
                            const scope = module.scopeId;
                            void module.action(async () => {
                              const result = await api<Revealed>(
                                `/v1/scopes/${scope}/recovery-keys/${key.id}/reveal`,
                                { reason },
                                "POST",
                              );
                              if (isCurrent() && selectedScope.current === scope && !document.hidden)
                                setRevealed(result);
                            });
                          }}
                        >
                          Reveal
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
          {!module.data.keys.length && <p>No recovery keys have been escrowed.</p>}
          {revealed && (
            <div role="status">
              <h3>{revealed.volume} recovery key</h3>
              <p>{revealed.protectorId}</p>
              <output>{revealed.recoveryKey}</output>
              <p>This value hides after 30 seconds or when this page loses visibility.</p>
              <button type="button" onClick={() => setRevealed(null)}>
                Hide now
              </button>
            </div>
          )}
        </>
      )}
    </section>
  );
}
