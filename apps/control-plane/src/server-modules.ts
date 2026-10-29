import type { Command } from "@one-control/protocol";
import { definition as applicationUpdates } from "../../../modules/application-updates/definition.js";
import { definition as assetManagement } from "../../../modules/asset-management/definition.js";
import { definition as commandHost } from "../../../modules/command-host/definition.js";
import { definition as deployment } from "../../../modules/deployment/definition.js";
import { definition as desktopPolicies } from "../../../modules/desktop-policies/definition.js";
import { definition as ema } from "../../../modules/ema/definition.js";
import { definition as falcon } from "../../../modules/falcon/definition.js";
import { definition as falconEvents } from "../../../modules/falcon-events/definition.js";
import { definition as falconSync } from "../../../modules/falcon-sync/definition.js";
import { definition as indexing } from "../../../modules/indexing/definition.js";
import { definition as integrationHttp } from "../../../modules/integration-http/definition.js";
import { definition as inventory } from "../../../modules/inventory/definition.js";
import { definition as nativeDispatch } from "../../../modules/native-dispatch/definition.js";
import { definition as nativeDistribution } from "../../../modules/native-distribution/definition.js";
import { definition as nativeObservations } from "../../../modules/native-observations/definition.js";
import { definition as observations } from "../../../modules/observations/definition.js";
import { definition as recoveryEscrow } from "../../../modules/recovery-escrow/definition.js";
import { definition as storeUpdates } from "../../../modules/store-updates/definition.js";
import { definition as userSessions } from "../../../modules/user-session-host/definition.js";
import { definition as windowsUpdates } from "../../../modules/windows-updates/definition.js";
import { createModuleRegistry } from "./module-registry.js";

export const commandModules = {
  "inventory.scan": "inventory",
  "sessions.list": "user-session-host",
  "applications.check": "application-updates",
  "applications.upgrade": "application-updates",
  "windows.scan": "windows-updates",
  "windows.install": "windows-updates",
  "indexing.status": "indexing",
  "indexing.enable": "indexing",
  "indexing.disable": "indexing",
  "indexing.pause": "indexing",
  "indexing.resume": "indexing",
  "winget.upgrade": "application-updates",
  "store.upgrade": "store-updates",
  "package.install": "deployment",
} satisfies Record<Command["kind"], string>;
const featureDefinitions = [
  recoveryEscrow,
  nativeDispatch,
  nativeObservations,
  nativeDistribution,
  falconSync,
  falconEvents,
  assetManagement,
  desktopPolicies,
  observations,
  commandHost,
  integrationHttp,
  inventory,
  indexing,
  userSessions,
  windowsUpdates,
  applicationUpdates,
  storeUpdates,
  deployment,
  falcon,
  ema,
];
export const serverModules = createModuleRegistry(
  featureDefinitions.map((definition) => ({
    ...definition,
    commands: Object.entries(commandModules)
      .filter(([, owner]) => owner === definition.id)
      .map(([command]) => command),
    background: definition.id === "falcon-sync" ? ["falcon.sync"] : [],
  })),
);
