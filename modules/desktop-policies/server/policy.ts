// SPDX-License-Identifier: GPL-3.0-only
// Adapted from TIBCON Sentry desktop policy semantics; see docs/sentry-integration.json.
import { createHash } from "node:crypto";
import { z } from "zod";

export const policyId = z.string().regex(/^[a-z0-9][a-z0-9-]{1,62}$/);
const list = z
  .array(z.string().trim().min(1).max(255))
  .max(500)
  .transform((items) => [...new Set(items.map((item) => item.toLowerCase()))].sort());
export const siteCategories = [
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
] as const;
const apps = z
  .strictObject({
    enabled: z.boolean().default(false),
    mode: z.enum(["allowlist", "denylist"]).default("denylist"),
    allow: list.default([]),
    deny: list.default([]),
  })
  .prefault({})
  .superRefine((value, context) => {
    if (value.enabled && value.mode === "allowlist" && !value.allow.length)
      context.addIssue({ code: "custom", message: "An enabled allowlist requires applications" });
  });
const web = z
  .strictObject({
    enabled: z.boolean().default(false),
    blockedCategories: z
      .array(z.enum(siteCategories))
      .max(10)
      .default([])
      .transform((items) => [...new Set(items)].sort()),
    blockedDomains: list.default([]),
  })
  .prefault({});
const bitlocker = z
  .strictObject({
    mode: z.enum(["unmanaged", "protected", "suspended", "decrypted"]).default("unmanaged"),
    backupRecoveryKey: z.boolean().default(false),
    rotateRecoveryKeyDays: z.union([z.literal(0), z.number().int().min(30).max(365)]).default(0),
    encryptionMethod: z.enum(["xts_aes_128", "xts_aes_256"]).default("xts_aes_256"),
    encryptUsedSpaceOnly: z.boolean().default(true),
  })
  .prefault({});
export const desktopPolicyInput = z
  .strictObject({
    displayName: z.string().trim().min(1).max(120),
    apps,
    web,
    hardening: z
      .strictObject({
        bitlocker,
        usbStorage: z.enum(["unmanaged", "allowed", "blocked"]).default("unmanaged"),
        windowsUpdate: z.enum(["unmanaged", "managed"]).default("unmanaged"),
      })
      .prefault({}),
    monitoring: z
      .strictObject({
        foregroundTracking: z.boolean().default(false),
        inventory: z.boolean().default(false),
        screenshots: z.boolean().default(false),
        screenshotIntervalSec: z.number().int().min(30).max(3600).default(300),
        idleThresholdSec: z.number().int().min(30).max(3600).default(300),
        perAppExclusions: list.default([]),
        notice: z.string().trim().max(4000).default(""),
        retentionDays: z.number().int().min(1).max(3650).nullable().default(null),
      })
      .prefault({}),
    confirmBitlockerDecryption: z.boolean().optional(),
    confirmBitlockerSuspension: z.boolean().optional(),
  })
  .superRefine((value, context) => {
    if (value.hardening.bitlocker.mode === "decrypted" && value.confirmBitlockerDecryption !== true)
      context.addIssue({ code: "custom", message: "Drive decryption requires explicit confirmation" });
    if (value.hardening.bitlocker.mode === "suspended" && value.confirmBitlockerSuspension !== true)
      context.addIssue({ code: "custom", message: "BitLocker suspension requires explicit confirmation" });
    if ((value.monitoring.screenshots || value.monitoring.foregroundTracking) && !value.monitoring.notice)
      context.addIssue({ code: "custom", message: "Monitoring requires a visible user notice" });
    if (
      (value.monitoring.screenshots || value.monitoring.foregroundTracking) &&
      value.monitoring.retentionDays === null
    )
      context.addIssue({ code: "custom", message: "Select monitoring retention explicitly" });
  });
export type DesktopPolicy = Omit<
  z.output<typeof desktopPolicyInput>,
  "confirmBitlockerDecryption" | "confirmBitlockerSuspension"
>;

export function buildDesktopPolicy(raw: unknown): DesktopPolicy {
  const {
    confirmBitlockerDecryption: _decryption,
    confirmBitlockerSuspension: _suspension,
    ...document
  } = desktopPolicyInput.parse(raw);
  return document;
}
export function policyDigest(document: DesktopPolicy) {
  return createHash("sha256").update(JSON.stringify(document)).digest("hex");
}
/** Desired modules only. Selecting a policy never grants permissions or activates a payload. */
export function policyModules(document: DesktopPolicy): string[] {
  const modules: string[] = [];
  if (document.apps.enabled) modules.push("application-control");
  if (document.web.enabled) modules.push("web-filtering");
  if (
    document.hardening.bitlocker.mode !== "unmanaged" ||
    document.hardening.bitlocker.backupRecoveryKey ||
    document.hardening.bitlocker.rotateRecoveryKeyDays
  )
    modules.push("bitlocker");
  if (document.hardening.usbStorage !== "unmanaged") modules.push("device-control");
  if (document.hardening.windowsUpdate !== "unmanaged") modules.push("windows-updates");
  if (document.monitoring.foregroundTracking) modules.push("activity-monitoring");
  if (document.monitoring.screenshots) modules.push("screen-capture");
  if (document.monitoring.inventory) modules.push("inventory");
  return modules;
}
export const desktopPolicyTemplates = [
  { id: "unmanaged", document: buildDesktopPolicy({ displayName: "Unmanaged" }) },
  {
    id: "standard",
    document: buildDesktopPolicy({
      displayName: "Standard managed",
      hardening: { bitlocker: { mode: "protected", backupRecoveryKey: true }, windowsUpdate: "managed" },
    }),
  },
  {
    id: "restricted",
    document: buildDesktopPolicy({
      displayName: "Restricted applications",
      apps: {
        enabled: true,
        mode: "allowlist",
        allow: [
          "explorer.exe",
          "msedge.exe",
          "chrome.exe",
          "outlook.exe",
          "teams.exe",
          "winword.exe",
          "excel.exe",
        ],
      },
      web: {
        enabled: true,
        blockedCategories: ["malware", "phishing", "adult", "gambling", "file-sharing", "proxy-vpn"],
      },
    }),
  },
];

/** Classification is a display hint from installed-app names, never an enforcement verdict. */
export function classifyAppControl(
  app: { name: string; publisher?: string | null },
  rules: DesktopPolicy["apps"],
) {
  if (!rules.enabled || (rules.mode === "denylist" && !rules.deny.length)) return "unrestricted";
  const name = app.name.toLowerCase();
  const match = (entry: string) => {
    const token = entry.replace(/\.exe$/, "");
    return (
      name.split(/[^a-z0-9]+/).includes(token) ||
      name.replace(/\s+/g, "").includes(token) ||
      (app.publisher ?? "").toLowerCase().includes(token)
    );
  };
  return rules.mode === "allowlist"
    ? rules.allow.some(match)
      ? "allowed"
      : "blocked"
    : rules.deny.some(match)
      ? "blocked"
      : "allowed";
}
