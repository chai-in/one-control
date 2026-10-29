import { useEffect, useState } from "react";
import type { ScopedApi } from "./use-scoped-module.js";

export function NativeEnrollment({ api, isCurrent }: { api: ScopedApi; isCurrent: () => boolean }) {
  const [scopes, setScopes] = useState<{ id: string; name: string }[]>([]),
    [scopeId, setScopeId] = useState(""),
    [hostname, setHostname] = useState(""),
    [platform, setPlatform] = useState("win-x64"),
    [machineId, setMachineId] = useState(""),
    [deviceId, setDeviceId] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const [invitation, setInvitation] = useState<{ token: string; deviceId: string; expiresAt: string } | null>(
    null,
  );
  useEffect(() => {
    let live = true;
    api<{ scopes: { id: string; name: string }[] }>("/v1/scopes")
      .then((value) => {
        if (live && isCurrent()) setScopes(value.scopes);
      })
      .catch((failure) => {
        if (live && isCurrent()) setError(failure.message);
      });
    return () => {
      live = false;
    };
  }, [api, isCurrent]);
  useEffect(() => {
    if (!invitation) return;
    const timer = setTimeout(
      () => setInvitation(null),
      Math.max(0, Date.parse(invitation.expiresAt) - Date.now()),
    );
    return () => clearTimeout(timer);
  }, [invitation]);
  return (
    <div className="desktop-panel">
      <p>
        Create a one-time invitation for an exact computer and management scope. The installation owner
        supplies the machine identity and provisions the native credential.
      </p>
      {error && <p role="alert">{error}</p>}
      {invitation ? (
        <div>
          <label>
            One-time invitation
            <textarea readOnly value={invitation.token} />
          </label>
          <p>Device {invitation.deviceId}</p>
          <p>
            Expires {new Date(invitation.expiresAt).toLocaleString()}. Pass securely to the installation
            owner. This value is held only in this page's memory.
          </p>
          <button type="button" onClick={() => setInvitation(null)}>
            Hide invitation
          </button>
        </div>
      ) : (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            setBusy(true);
            setError("");
            void (async () => {
              try {
                const bytes = crypto.getRandomValues(new Uint8Array(32));
                const token = btoa(String.fromCharCode(...bytes))
                  .replaceAll("+", "-")
                  .replaceAll("/", "_")
                  .replaceAll("=", "");
                const digest = new Uint8Array(
                  await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)),
                );
                const tokenHash = [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
                const result = await api<{ deviceId: string; expiresAt: string }>(
                  `/v1/scopes/${scopeId}/native-invitations`,
                  { tokenHash, hostname, platform, machineId, ...(deviceId ? { deviceId } : {}) },
                  "POST",
                );
                if (isCurrent()) setInvitation({ ...result, token });
              } catch (failure) {
                if (isCurrent()) setError((failure as Error).message);
              } finally {
                if (isCurrent()) setBusy(false);
              }
            })();
          }}
        >
          <label>
            Management scope
            <select
              required
              disabled={busy}
              value={scopeId}
              onChange={(event) => setScopeId(event.target.value)}
            >
              <option value="">Select scope</option>
              {scopes.map((scope) => (
                <option key={scope.id} value={scope.id}>
                  {scope.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Computer name
            <input
              required
              maxLength={255}
              disabled={busy}
              value={hostname}
              onChange={(event) => setHostname(event.target.value)}
            />
          </label>
          <label>
            Platform
            <select disabled={busy} value={platform} onChange={(event) => setPlatform(event.target.value)}>
              {["win-x64", "win-arm64", "osx-x64", "osx-arm64", "linux-x64", "linux-arm64"].map((value) => (
                <option key={value}>{value}</option>
              ))}
            </select>
          </label>
          <label>
            Machine identity from installation owner
            <input
              required
              maxLength={128}
              disabled={busy}
              value={machineId}
              onChange={(event) => setMachineId(event.target.value)}
            />
          </label>
          <label>
            Existing device ID, for replacement enrollment only
            <input disabled={busy} value={deviceId} onChange={(event) => setDeviceId(event.target.value)} />
          </label>
          <p>
            Replacement enrollment also requires the computer's currently authorized credential when this
            invitation is redeemed. It preserves the device's scope.
          </p>
          <button type="submit" disabled={busy || !scopeId}>
            Create native invitation
          </button>
        </form>
      )}
    </div>
  );
}
