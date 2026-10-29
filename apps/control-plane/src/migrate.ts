import { parseConfig } from "./config.js";
import { migrate, openDatabase } from "./database.js";
import { finishCleanup, type PrimaryFailure } from "./entrypoint-cleanup.js";

const config = parseConfig(process.env);
const db = await openDatabase(config.DATABASE_URL, config.LOCAL_DB_PATH);
let primary: PrimaryFailure = { failed: false };
try {
  await migrate(db);
} catch (error) {
  primary = { failed: true, error };
}
await finishCleanup(primary, [() => db.close()]);
console.log("Database migrations applied");
