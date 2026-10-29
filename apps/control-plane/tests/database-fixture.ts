import { type Database, migrate, openDatabase } from "../src/database.js";
import { openPostgresFixture } from "./postgres-fixture.js";

export async function openTestDatabase(): Promise<Database> {
  if (process.env.ONE_CONTROL_POSTGRES_PROFILE) return openPostgresFixture();
  if (process.env.TEST_DATABASE_URL && process.env.TEST_DATABASE_URL !== "local") {
    throw new Error("Unverified TEST_DATABASE_URL rejected. Use the owned PostgreSQL runner.");
  }
  const db = await openDatabase("local");
  try {
    await migrate(db);
    return db;
  } catch (error) {
    await db.close();
    throw error;
  }
}
