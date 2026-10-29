import {
  type BatchReview,
  commandSchema,
  contextSchema,
  type Device,
  type Job,
  ringSchema,
  type WorkspaceInfo,
} from "@one-control/protocol";
import {
  Activity,
  ArrowUpRight,
  Box,
  Check,
  ChevronRight,
  ClipboardList,
  Download,
  LayoutDashboard,
  Lock,
  Monitor,
  Plus,
  RefreshCw,
  Shield,
  Users,
  X,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { AssetsPanel } from "../../../modules/asset-management/console/AssetsPanel.js";
import { DesktopPanel } from "../../../modules/desktop-policies/console/DesktopPanel.js";
import { ApprovalReview } from "../../../modules/native-dispatch/console/ApprovalReview.js";
import { JobForm } from "../../../modules/native-dispatch/console/JobForm.js";
import { OperationDetails } from "../../../modules/native-dispatch/console/OperationDetails.js";
import { OperationsTable } from "../../../modules/native-dispatch/console/OperationsTable.js";
import { NativeModulesPanel } from "../../../modules/native-distribution/console/NativeModulesPanel.js";
import { NativeInventoryPanel } from "../../../modules/native-observations/console/NativeInventoryPanel.js";
import { RecoveryKeysPanel } from "../../../modules/recovery-escrow/console/RecoveryKeysPanel.js";
import { HttpError } from "./api-errors.js";
import { completeSignIn, identity } from "./auth.js";
import { Empty, Stat } from "./components.js";
import { DeviceDetails } from "./DeviceDetails.js";
import { Dialog } from "./Dialog.js";
import { FleetTable } from "./FleetTable.js";
import { NativeEnrollment } from "./NativeEnrollment.js";
import { ScopedIntegrationPanel } from "./ScopedIntegrationPanel.js";
import { ScopesPanel } from "./ScopesPanel.js";
import { failed, pending as loadingSection, type Section, SectionNotice, snapshot } from "./section-state.js";
import { useSessionApi } from "./use-session-api.js";
import {
  type Audit,
  date,
  jobStates,
  labels,
  type OperationDraft,
  type Release,
  record,
  relativeTime,
  short,
} from "./view-model.js";

function collection<T>(value: T[], valid: (row: T) => boolean): T[] {
  if (!Array.isArray(value) || !value.every((row) => record(row) && valid(row)))
    throw new Error("The control plane returned invalid collection data.");
  return value;
}

function validJob(job: Job) {
  return (
    [job.id, job.device_id, job.batch_id, job.created_by, job.created_at, job.starts_at, job.ends_at].every(
      (value) => typeof value === "string",
    ) &&
    Object.hasOwn(jobStates, job.state) &&
    contextSchema.safeParse(job.context).success &&
    commandSchema.safeParse(job.command).success &&
    job.command.kind === job.kind &&
    (job.result === null || record(job.result) !== null)
  );
}

function validDevice(device: Device) {
  return (
    typeof device.id === "string" &&
    typeof device.hostname === "string" &&
    ringSchema.safeParse(device.ring).success &&
    (device.last_seen_at === null || typeof device.last_seen_at === "string") &&
    (device.revoked_at === null || typeof device.revoked_at === "string") &&
    (device.inventory === null || record(device.inventory) !== null)
  );
}

function validAudit(event: Audit) {
  return (
    typeof event.sequence === "number" &&
    [event.actor, event.action, event.subject, event.created_at].every((value) => typeof value === "string")
  );
}

function validRelease(release: Release) {
  return (
    typeof release.sequence === "number" &&
    [release.id, release.package_id, release.manifest?.version, release.manifest?.expiresAt].every(
      (value) => typeof value === "string",
    )
  );
}

type Tab =
  | "overview"
  | "fleet"
  | "updates"
  | "releases"
  | "audit"
  | "falcon"
  | "ema"
  | "desktop"
  | "assets"
  | "native"
  | "native-inventory"
  | "scopes"
  | "recovery-keys";
type DialogDependency = "jobs" | "workspace" | "releases";
const navigation = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "fleet", label: "Device fleet", icon: Monitor },
  { id: "desktop", label: "Desktop policies", icon: Shield },
  { id: "assets", label: "Assets and people", icon: Users },
  { id: "native", label: "Native modules", icon: Box },
  { id: "scopes", label: "Management scopes", icon: Users },
  { id: "native-inventory", label: "Native inventory", icon: Monitor },
  { id: "recovery-keys", label: "Recovery keys", icon: Lock },
  { id: "updates", label: "Update operations", icon: Download },
  { id: "releases", label: "Release catalogue", icon: Box },
  { id: "audit", label: "Audit trail", icon: ClipboardList },
  { id: "falcon", label: "CrowdStrike", icon: Shield },
  { id: "ema", label: "Intel EMA", icon: Monitor },
] as const;
export function App() {
  const [draft, setDraft] = useState("");
  const [tab, setTab] = useState<Tab>("overview");
  const [me, setMe] = useState<{ subject: string; roles: string[] } | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [jobsSection, setJobs] = useState<Section<Job[]>>({ status: "idle" });
  const [auditSection, setAudit] = useState<Section<Audit[]>>({ status: "idle" });
  const [releasesSection, setReleases] = useState<Section<Release[]>>({ status: "idle" });
  const [error, setError] = useState("");
  const [connectionError, setConnectionError] = useState("");
  const [busy, setBusy] = useState(false);
  const [workspaceSection, setWorkspace] = useState<Section<WorkspaceInfo>>({ status: "idle" });
  const [coreCurrent, setCoreCurrent] = useState(false);
  const jobs = snapshot(jobsSection)?.data ?? [];
  const audit = snapshot(auditSection)?.data ?? [];
  const releases = snapshot(releasesSection)?.data ?? [];
  const workspace = snapshot(workspaceSection)?.data;
  const jobsAvailable = snapshot(jobsSection) !== undefined;
  const releasesAvailable = snapshot(releasesSection) !== undefined;
  const auditAvailable = snapshot(auditSection) !== undefined;
  const [operationDraft, setOperationDraft] = useState<OperationDraft | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const loadSequence = useRef(0);
  const dialogAuthority = useRef({ jobs: 0, workspace: 0, releases: 0 });
  const loading = useRef(false);
  const [modal, setModal] = useState<"enroll" | "job" | "release" | null>(null);
  const [detail, setDetail] = useState<Job | Device | null>(null);
  const [review, setReview] = useState<BatchReview | null>(null);
  const clearData = useCallback((reason?: string) => {
    setMe(null);
    setDevices([]);
    setJobs({ status: "idle" });
    setAudit({ status: "idle" });
    setReleases({ status: "idle" });
    setDetail(null);
    setReview(null);
    setModal(null);
    setDraft("");
    setWorkspace({ status: "idle" });
    setCoreCurrent(false);
    setOperationDraft(null);
    setLastUpdated(null);
    setRefreshing(false);
    loadSequence.current++;
    dialogAuthority.current.jobs++;
    dialogAuthority.current.workspace++;
    dialogAuthority.current.releases++;
    loading.current = false;
    setBusy(false);
    setError(reason ?? "");
    setConnectionError("");
    setTab("overview");
  }, []);
  const { token, replaceToken: setToken, api, isCurrent } = useSessionApi(clearData);
  async function signOut() {
    setToken("");
    try {
      await identity?.removeUser();
      await identity?.clearStaleState();
      if (identity) await identity.signoutRedirect();
    } catch {
      setError("The console is signed out. Your organisation sign-out page could not be reached.");
    }
  }
  const load = useCallback(
    async (force = false) => {
      if (!token || (loading.current && !force)) return;
      loading.current = true;
      const sequence = ++loadSequence.current;
      setRefreshing(true);
      setCoreCurrent(false);
      setJobs(loadingSection);
      setAudit(loadingSection);
      setReleases(loadingSection);
      setWorkspace(loadingSection);
      const current = () => isCurrent() && sequence === loadSequence.current;
      let optionalStarted = false;
      try {
        async function required<T>(request: Promise<T>) {
          try {
            return await request;
          } catch (caught) {
            if (current() && caught instanceof HttpError && caught.status === 403)
              setToken("", "Access to identity or fleet was denied. Sign in with an authorised account.");
            throw caught;
          }
        }
        const [actor, fleet] = await Promise.all([
          required(api<{ subject: string; roles: string[] }>("/v1/me")),
          required(api<{ devices: Device[] }>("/v1/devices")),
        ]);
        if (!current()) return;
        if (
          !actor ||
          typeof actor.subject !== "string" ||
          !Array.isArray(actor.roles) ||
          !actor.roles.every((role) => typeof role === "string") ||
          !fleet ||
          !Array.isArray(fleet.devices)
        )
          throw new Error("The control plane returned invalid identity or fleet data.");
        const confirmedDevices = collection(fleet.devices, validDevice);
        setLastUpdated(new Date().toISOString());
        setMe(actor);
        setDevices(confirmedDevices);
        setCoreCurrent(true);
        setConnectionError("");
        async function optional<T>(
          read: () => Promise<T>,
          publish: (update: (previous: Section<T>) => Section<T>) => void,
          denied?: () => void,
        ) {
          try {
            const data = await read();
            if (data === undefined || data === null)
              throw new Error("The control plane returned invalid collection data.");
            if (current())
              publish(() => ({ status: "loaded", snapshot: { data, updatedAt: new Date().toISOString() } }));
          } catch (caught) {
            if (!current()) return;
            publish((previous) => failed(previous, caught));
            if (caught instanceof HttpError && [403, 404, 405, 501].includes(caught.status)) denied?.();
          }
        }
        const optionalRequests: Promise<void>[] = [];
        optionalRequests.push(
          optional(
            async () => collection((await api<{ jobs: Job[] }>("/v1/jobs"))?.jobs, validJob),
            setJobs,
            () => {
              dialogAuthority.current.jobs++;
              setDetail((previous) => (previous && !("hostname" in previous) ? null : previous));
              setReview(null);
              setOperationDraft(null);
              setModal((previous) => (previous === "job" ? null : previous));
            },
          ),
        );
        optionalRequests.push(
          optional(
            async () =>
              collection((await api<{ events: Audit[] }>("/v1/audit?direction=latest"))?.events, validAudit),
            setAudit,
          ),
        );
        optionalRequests.push(
          optional(
            async () =>
              collection((await api<{ releases: Release[] }>("/v1/releases"))?.releases, validRelease),
            setReleases,
            () => {
              dialogAuthority.current.releases++;
              setModal((previous) => (previous === "release" || previous === "job" ? null : previous));
              setOperationDraft(null);
            },
          ),
        );
        optionalRequests.push(
          optional(
            async () => {
              const settings = await api<WorkspaceInfo>("/v1/workspace");
              if (
                !settings ||
                !["poc", "production"].includes(settings.deploymentStage) ||
                (settings.deviceLimit !== null &&
                  (typeof settings.deviceLimit !== "number" ||
                    !Number.isFinite(settings.deviceLimit) ||
                    settings.deviceLimit < 0))
              )
                throw new Error("The control plane returned invalid workspace settings.");
              return settings;
            },
            setWorkspace,
            () => {
              dialogAuthority.current.workspace++;
              setModal(null);
              setOperationDraft(null);
            },
          ),
        );
        optionalStarted = true;
        void Promise.all(optionalRequests).finally(() => {
          if (current()) {
            setRefreshing(false);
            loading.current = false;
          }
        });
      } catch (caught) {
        if (!current()) return;
        if (caught instanceof HttpError && caught.status === 403) {
          setToken("", "Access to identity or fleet was denied. Sign in with an authorised account.");
          return;
        }
        const message = caught instanceof Error ? caught.message : "Connection failed";
        setConnectionError(message);
        const skipped = new Error("Not refreshed because identity or fleet could not refresh.");
        setJobs((previous) => failed(previous, skipped));
        setAudit((previous) => failed(previous, skipped));
        setReleases((previous) => failed(previous, skipped));
        setWorkspace((previous) => failed(previous, skipped));
      } finally {
        if (current() && !optionalStarted) {
          setRefreshing(false);
          loading.current = false;
        }
      }
    },
    [api, token, isCurrent, setToken],
  );
  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 15_000);
    return () => window.clearInterval(timer);
  }, [load]);
  useEffect(() => {
    if (identity && window.location.pathname === "/auth/callback")
      void completeSignIn()
        .then((user) => {
          setToken(user.access_token);
          window.history.replaceState({}, "", "/");
        })
        .catch(() => setError("Sign-in could not be completed"));
  }, [setToken]);
  useEffect(() => {
    const expired = () => setToken("");
    identity?.events.addAccessTokenExpired(expired);
    return () => identity?.events.removeAccessTokenExpired(expired);
  }, [setToken]);
  async function action(
    work: (current: () => boolean) => Promise<void>,
    dependencies: DialogDependency[] = ["jobs"],
  ) {
    if (!coreCurrent) return;
    const authority = { ...dialogAuthority.current };
    const current = () =>
      isCurrent() && dependencies.every((key) => authority[key] === dialogAuthority.current[key]);
    setBusy(true);
    setError("");
    try {
      await work(current);
      if (!current()) return;
      await load(true);
    } catch (caught) {
      if (!isCurrent()) return;
      setError(caught instanceof Error ? caught.message : "Operation failed");
    } finally {
      if (isCurrent()) setBusy(false);
    }
  }
  const inputsCurrent =
    coreCurrent &&
    jobsSection.status === "loaded" &&
    releasesSection.status === "loaded" &&
    workspaceSection.status === "loaded";
  const mutationBusy = busy || !inputsCurrent;
  const operator = Boolean(me?.roles.includes("operator"));
  const approver = Boolean(me?.roles.includes("approver"));
  const active = jobs.filter((job) => ["queued", "leased"].includes(job.state)).length;
  const pending = new Set(jobs.filter((job) => job.state === "awaiting_approval").map((job) => job.batch_id))
    .size;
  const online = devices.filter(
    (device) =>
      device.last_seen_at && Date.now() - Date.parse(device.last_seen_at) < 120_000 && !device.revoked_at,
  ).length;
  const title = navigation.find((item) => item.id === tab)?.label;
  const summary = jobs.reduce<Record<string, number>>((all, job) => {
    all[job.kind] = (all[job.kind] ?? 0) + 1;
    return all;
  }, {});
  if (!token || !me)
    return (
      <div className="login">
        <div className="login-card">
          <div className="brand">
            <Shield size={30} />
            <span>One Control</span>
          </div>
          <div className="eyebrow">One Control · FLEET OPERATIONS</div>
          <h1>
            One view.
            <br />
            Every managed computer.
          </h1>
          <p>
            This optional console is for IT and authorised employees. Background agents operate independently.
          </p>
          {identity ? (
            <button type="button" className="primary" onClick={() => void identity?.signinRedirect()}>
              Sign in with your organisation <ArrowUpRight size={16} />
            </button>
          ) : import.meta.env.DEV ||
            (import.meta.env.MODE === "private-preview" &&
              ["127.0.0.1", "localhost", "[::1]"].includes(window.location.hostname)) ? (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                setToken(draft);
                setDraft("");
              }}
            >
              <label htmlFor="token">Local development access token</label>
              <input
                id="token"
                type="password"
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
                autoComplete="off"
                required
              />
              <button type="submit" className="primary">
                Open operations console <ArrowUpRight size={16} />
              </button>
            </form>
          ) : (
            <p className="error">
              Organisation sign-in is not configured. IT must configure the console’s OIDC provider.
            </p>
          )}
          {token && (
            <button type="button" className="secondary" onClick={() => void load(true)}>
              Retry current session
            </button>
          )}
          {(error || connectionError) && (
            <p className="error" role="alert">
              {error || connectionError}
            </p>
          )}
          <div className="login-note">
            <Lock size={13} /> Access is authenticated. Every change is recorded.
          </div>
        </div>
        <div className="login-art">
          <div className="orbit">
            <Shield size={70} />
          </div>
          <span>SYSTEM AGENT + OPTIONAL IT CONSOLE</span>
        </div>
      </div>
    );
  const actor = me.subject;
  const allowBroaderRings =
    coreCurrent && workspaceSection.status === "loaded" && workspace?.deploymentStage === "production";
  function openOperation(draft: OperationDraft | null = null) {
    if (!inputsCurrent) return;
    setError("");
    setDetail(null);
    setOperationDraft(draft);
    setModal("job");
  }
  function jobTable(items: Job[], compact = false) {
    return (
      <OperationsTable
        jobs={items}
        devices={devices}
        actor={actor}
        operator={operator}
        approver={approver}
        busy={mutationBusy}
        compact={compact}
        open={setDetail}
        review={(job) =>
          void action(async (current) => {
            const result = await api<BatchReview>(`/v1/batches/${job.batch_id}`);
            if (current()) setReview(result);
          })
        }
        cancel={(job) =>
          void action(async () => {
            await api(`/v1/batches/${job.batch_id}/cancel`, {});
          })
        }
      />
    );
  }
  return (
    <div className="shell">
      <aside>
        <div className="brand">
          <Shield size={26} />
          <span>One Control</span>
        </div>
        <div className="workspace-label">One Control workspace</div>
        <nav>
          {navigation.map((item) => (
            <button
              type="button"
              key={item.id}
              aria-label={item.label}
              className={tab === item.id ? "selected" : ""}
              onClick={() => setTab(item.id)}
            >
              <item.icon size={18} />
              {item.label}
              {item.id === "updates" && pending > 0 && <span className="nav-count">{pending}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="system-note">
            <span className="dot" /> Optional operations console
          </div>
          <small>SYSTEM agents run independently.</small>
          <button type="button" onClick={() => void signOut()}>
            Sign out · {me.subject}
          </button>
        </div>
      </aside>
      <div className="main">
        <header>
          <div className="breadcrumb">
            Workspace <ChevronRight size={12} />
            <strong>{title}</strong>
          </div>
          <div className="header-right">
            <span className="role">
              <Users size={13} />
              {me.roles.filter((role) => role !== "viewer").join(" / ") || "viewer"}
            </span>
            <button
              type="button"
              className="icon-button"
              aria-label="Refresh data"
              onClick={() => void load(true)}
            >
              <RefreshCw size={16} className={refreshing ? "refreshing" : ""} />
            </button>
            <span className="avatar">IT</span>
          </div>
        </header>
        {workspace?.deploymentStage === "poc" && (
          <div className="workspace-banner">
            <Lock size={15} />
            <strong>Proof of concept</strong>
            <span>
              Canary devices only · {devices.filter((device) => !device.revoked_at).length} /{" "}
              {workspace.deviceLimit} enrolled · Fleet deployment awaits approval
            </span>
          </div>
        )}
        <main>
          <div className="page-heading">
            <div>
              <div className="eyebrow">COMPUTER MANAGEMENT</div>
              <h1>{tab === "overview" ? "Fleet overview" : title}</h1>
              <p>
                {tab === "overview"
                  ? "Know what’s running. Control what changes."
                  : "Authenticated operations, durable receipts, and a complete history."}
              </p>
            </div>
            <div className="heading-actions">
              {operator && (
                <button
                  type="button"
                  className="secondary"
                  disabled={busy || !coreCurrent || workspaceSection.status !== "loaded"}
                  onClick={() => {
                    setModal("enroll");
                  }}
                >
                  <Plus size={15} />
                  Enroll computer
                </button>
              )}
              {operator && (
                <button
                  type="button"
                  className="primary"
                  disabled={mutationBusy}
                  onClick={() => openOperation()}
                >
                  <Plus size={15} />
                  New operation
                </button>
              )}
            </div>
          </div>
          {(error || connectionError) && !modal && !detail && !review && (
            <div className="error-banner" role="alert">
              {error || connectionError}
              <button
                type="button"
                onClick={() => {
                  setError("");
                  setConnectionError("");
                }}
                aria-label="Dismiss error"
              >
                <X size={15} />
              </button>
            </div>
          )}
          <section className="section-statuses" aria-label="Collection status">
            <SectionNotice name="Operations" section={jobsSection} />
            <SectionNotice name="Audit" section={auditSection} />
            <SectionNotice name="Releases" section={releasesSection} />
            <SectionNotice name="Workspace settings" section={workspaceSection} />
          </section>
          {!coreCurrent && (
            <p className="notice">
              Fleet data is stale or refreshing. Changes are unavailable until the required refresh succeeds.
            </p>
          )}
          {tab === "overview" && (
            <>
              <div className="stats">
                <Stat
                  label="Managed computers"
                  value={devices.filter((device) => !device.revoked_at).length}
                  icon={Monitor}
                  note={`${online} reporting in the last 2 minutes`}
                />
                <Stat
                  label="Active operations"
                  value={jobsAvailable ? active : null}
                  icon={Activity}
                  note="Queued or currently running"
                />
                <Stat
                  label="Awaiting approval"
                  value={jobsAvailable ? pending : null}
                  icon={Lock}
                  note="Batches requiring a separate approver"
                />
                <Stat
                  label="Needs attention"
                  value={
                    jobsAvailable
                      ? jobs.filter((job) => ["failed", "indeterminate"].includes(job.state)).length
                      : null
                  }
                  icon={Shield}
                  note="Failures and uncertain outcomes"
                />
              </div>
              <div className="overview-grid">
                <section className="panel">
                  <div className="panel-heading">
                    <h2>Update coverage</h2>
                    <span className="subtle">Managed providers</span>
                  </div>
                  {Object.entries(labels).map(([kind, label]) => (
                    <div className="provider-row" key={kind}>
                      <div className="provider-icon">
                        <Box size={17} />
                      </div>
                      <div>
                        <strong>{label}</strong>
                        <small>
                          {kind.startsWith("windows")
                            ? "SYSTEM service"
                            : kind === "package.install"
                              ? "Signed package + publisher verification"
                              : kind === "inventory.scan"
                                ? "Hardware and application inventory"
                                : "Scoped user-session broker"}
                        </small>
                      </div>
                      <span className="provider-count">
                        {jobsAvailable ? (summary[kind] ?? 0) : "Unavailable"}
                        <small>operations</small>
                      </span>
                    </div>
                  ))}
                </section>
                <section className="panel rollout">
                  <div className="panel-heading">
                    <h2>
                      {workspace?.deploymentStage === "poc"
                        ? "POC deployment boundary"
                        : "Rollout guardrails"}
                    </h2>
                    <Lock size={16} />
                  </div>
                  <div className="ring-path">
                    <span>01</span>
                    <div>
                      <strong>Canary</strong>
                      <p>A small, explicitly selected group.</p>
                    </div>
                  </div>
                  <div className="ring-path">
                    <span>02</span>
                    <div>
                      <strong>Pilot</strong>
                      <p>
                        {workspace?.deploymentStage === "poc"
                          ? "Disabled in this POC. Business deployment approval comes first."
                          : "Unlocked after the canary completes successfully."}
                      </p>
                    </div>
                  </div>
                  <div className="ring-path">
                    <span>03</span>
                    <div>
                      <strong>Broad</strong>
                      <p>
                        {workspace?.deploymentStage === "poc"
                          ? "Disabled in this POC. Fleet-wide deployment is a later decision."
                          : "Unlocked after the pilot completes successfully."}
                      </p>
                    </div>
                  </div>
                  <div className="guardrail">
                    <Check size={14} />
                    No forced reboot commands
                  </div>
                  <div className="guardrail">
                    <Check size={14} />
                    No arbitrary remote shell
                  </div>
                  <div className="guardrail">
                    <Check size={14} />
                    Uncertain installs require reconciliation
                  </div>
                </section>
              </div>
              <section className="panel">
                <div className="panel-heading">
                  <h2>Recent operations</h2>
                  <button type="button" className="text-button" onClick={() => setTab("updates")}>
                    View all <ArrowUpRight size={14} />
                  </button>
                </div>
                {jobsAvailable && jobTable(jobs, true)}
              </section>
            </>
          )}
          {tab === "fleet" && <FleetTable devices={devices} open={setDetail} />}
          {tab === "updates" && (
            <section className="panel">
              <div className="panel-heading">
                <h2>Operation history</h2>
                <span className="subtle">Most recent 1,000 jobs</span>
              </div>
              {jobsAvailable && jobTable(jobs)}
            </section>
          )}
          {tab === "releases" && (
            <section className="panel">
              <div className="panel-heading">
                <h2>Trusted release catalogue</h2>
                {operator && (
                  <button
                    type="button"
                    className="small-button"
                    disabled={busy || !coreCurrent || releasesSection.status !== "loaded"}
                    onClick={() => setModal("release")}
                  >
                    <Plus size={13} />
                    Register signed release
                  </button>
                )}
              </div>
              {releasesAvailable && (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Package</th>
                        <th>Version</th>
                        <th>Sequence</th>
                        <th>Metadata expiry</th>
                      </tr>
                    </thead>
                    <tbody>
                      {releases.map((release) => (
                        <tr key={release.id}>
                          <td>
                            {release.package_id}
                            <small>{release.id}</small>
                          </td>
                          <td>{release.manifest.version}</td>
                          <td>{release.sequence}</td>
                          <td>{date(release.manifest.expiresAt)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {!releases.length && (
                    <Empty
                      icon={Box}
                      title="Trust comes before installation"
                      text="Register a signed MSI release for an approved internal application."
                    />
                  )}
                </div>
              )}
            </section>
          )}
          {tab === "audit" && (
            <section className="panel">
              <div className="panel-heading">
                <h2>Change history</h2>
                <span className="subtle">Latest 500 events · API supports cursor pagination</span>
              </div>
              {auditAvailable && (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Actor</th>
                        <th>Action</th>
                        <th>Subject</th>
                      </tr>
                    </thead>
                    <tbody>
                      {audit.map((event) => (
                        <tr key={event.sequence}>
                          <td>{date(event.created_at)}</td>
                          <td>{event.actor}</td>
                          <td>{event.action}</td>
                          <td>
                            <code>{short(event.subject)}</code>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {!audit.length && <p>No audit events returned.</p>}
                </div>
              )}
            </section>
          )}
          {tab === "desktop" && (
            <DesktopPanel api={api} isCurrent={isCurrent} canEdit={me?.roles.includes("operator") ?? false} />
          )}
          {tab === "assets" && (
            <AssetsPanel api={api} isCurrent={isCurrent} canEdit={me?.roles.includes("operator") ?? false} />
          )}
          {tab === "native" && (
            <NativeModulesPanel
              api={api}
              isCurrent={isCurrent}
              canEdit={me?.roles.includes("operator") ?? false}
            />
          )}
          {tab === "scopes" && (
            <ScopesPanel api={api} isCurrent={isCurrent} canEdit={me?.roles.includes("operator") ?? false} />
          )}
          {tab === "native-inventory" && (
            <NativeInventoryPanel
              api={api}
              isCurrent={isCurrent}
              canEdit={me?.roles.includes("operator") ?? false}
            />
          )}
          {tab === "recovery-keys" && (
            <RecoveryKeysPanel
              api={api}
              isCurrent={isCurrent}
              canEdit={me?.roles.includes("operator") ?? false}
            />
          )}
          {tab === "falcon" && (
            <ScopedIntegrationPanel
              key="falcon"
              kind="falcon"
              api={api}
              isCurrent={isCurrent}
              canEdit={me?.roles.includes("operator") ?? false}
            />
          )}
          {tab === "ema" && (
            <ScopedIntegrationPanel
              key="ema"
              kind="ema"
              api={api}
              isCurrent={isCurrent}
              canEdit={me?.roles.includes("operator") ?? false}
            />
          )}
          <footer>
            <span>
              <span className={`dot${connectionError ? " connection-stale" : ""}`} />{" "}
              {connectionError
                ? "Refresh failed — showing the last available data"
                : `Fleet updated ${relativeTime(lastUpdated).toLowerCase()} · ${
                    [jobsSection, auditSection, releasesSection, workspaceSection].some(
                      (section) => section.status === "loading",
                    )
                      ? "Some sections loading"
                      : [jobsSection, auditSection, releasesSection, workspaceSection].some(
                            (section) => section.status !== "loaded",
                          )
                        ? "Some sections unavailable"
                        : "All collections updated"
                  }`}
            </span>
            <span>
              {workspace?.deploymentStage === "poc" ? "Limited POC workspace" : "Windows fleet operations"}
            </span>
          </footer>
        </main>
      </div>
      {modal && (
        <Dialog
          title={
            modal === "enroll"
              ? "Enroll a computer"
              : modal === "job"
                ? "Create an operation"
                : "Register a signed release"
          }
          close={() => setModal(null)}
          wide={modal === "job"}
          busy={busy}
          error={error || connectionError}
        >
          {modal === "enroll" ? (
            <NativeEnrollment api={api} isCurrent={isCurrent} />
          ) : modal === "job" ? (
            <JobForm
              devices={devices}
              jobs={jobs}
              releases={releases}
              busy={mutationBusy}
              draft={operationDraft}
              allowBroaderRings={allowBroaderRings}
              onSubmit={(input, idempotencyKey) =>
                action(
                  async (current) => {
                    await api("/v1/batches", input, "POST", idempotencyKey);
                    if (!current()) return;
                    setModal(null);
                    setTab("updates");
                  },
                  ["jobs", "workspace", "releases"],
                )
              }
            />
          ) : (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                const data = new FormData(event.currentTarget);
                void action(
                  async (current) => {
                    await api("/v1/releases", JSON.parse(String(data.get("envelope"))));
                    if (!current()) return;
                    setModal(null);
                  },
                  ["releases"],
                );
              }}
            >
              <p>
                Paste the signed envelope produced by the offline release-signing tool. Its signature and
                allowed artifact origin are checked by the server.
              </p>
              <label htmlFor="release-envelope">Signed envelope</label>
              <textarea
                id="release-envelope"
                name="envelope"
                required
                placeholder={'{"payload":"…","signature":"…"}'}
              />
              <button
                type="submit"
                className="primary"
                disabled={busy || !coreCurrent || releasesSection.status !== "loaded"}
              >
                Verify and register
              </button>
            </form>
          )}
        </Dialog>
      )}
      {detail &&
        ("hostname" in detail || jobsAvailable) &&
        ("hostname" in detail ? (
          <DeviceDetails
            key={detail.id}
            device={devices.find((device) => device.id === detail.id) ?? detail}
            jobs={jobs}
            jobsAvailable={jobsAvailable}
            operator={operator && inputsCurrent}
            busy={busy}
            error={error || connectionError}
            allowBroaderRings={allowBroaderRings}
            close={() => setDetail(null)}
            createOperation={openOperation}
            openJob={setDetail}
            changeRing={(ring) =>
              action(async (current) => {
                if (detail.management_scope_id && detail.enrollment_id) {
                  const scope = await api<{ version: string }>(
                    `/v1/scopes/${detail.management_scope_id}/modules`,
                  );
                  await api(
                    `/v1/scopes/${detail.management_scope_id}/native-enrollments/${detail.enrollment_id}/ring`,
                    { ring, expectedVersion: scope.version },
                    "PATCH",
                  );
                } else await api(`/v1/devices/${detail.id}/ring`, { ring }, "PATCH");
                if (!current()) return;
                setDetail(null);
              })
            }
            revoke={() =>
              action(async (current) => {
                if (detail.management_scope_id && detail.enrollment_id)
                  await api(
                    `/v1/scopes/${detail.management_scope_id}/native-enrollments/${detail.enrollment_id}/revoke`,
                    {},
                  );
                else await api(`/v1/devices/${detail.id}/revoke`, {});
                if (!current()) return;
                setDetail(null);
              })
            }
          />
        ) : (
          <OperationDetails
            key={detail.id}
            job={jobs.find((job) => job.id === detail.id) ?? detail}
            device={devices.find((device) => device.id === detail.device_id)}
            operator={operator && inputsCurrent}
            busy={busy}
            error={error || connectionError}
            close={() => setDetail(null)}
            createOperation={openOperation}
            reconcile={(state, evidence) =>
              action(async (current) => {
                await api(`/v1/jobs/${detail.id}/reconcile`, { state, evidence });
                if (!current()) return;
                setDetail(null);
              })
            }
          />
        ))}
      {review && jobsAvailable && (
        <ApprovalReview
          key={review.id}
          review={review}
          busy={busy}
          mutationDisabled={!inputsCurrent}
          error={error || connectionError}
          close={() => setReview(null)}
          approve={() =>
            action(async (current) => {
              await api(`/v1/batches/${review.id}/approve`, { reviewDigest: review.reviewDigest });
              if (!current()) return;
              setReview(null);
            })
          }
        />
      )}
      <footer className="source-notice">
        <a href="https://github.com/chai-in/one-control" target="_blank" rel="noreferrer">
          Source code
        </a>
        {" · "}
        <a href="https://github.com/chai-in/one-control/blob/main/LICENSE" target="_blank" rel="noreferrer">
          AGPL-3.0
        </a>
        {" · Provided without warranty."}
      </footer>
    </div>
  );
}
