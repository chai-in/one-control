import { PGlite } from "@electric-sql/pglite";
import pg from "pg";
import { migrateOrdered } from "./migrations.js";

export interface TransactionQuery {
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: unknown[],
  ): Promise<T[]>;
}
export interface Database extends TransactionQuery {
  /** Trusted callbacks await all queries and leave transaction-control SQL to this owner. */
  transaction<T>(work: (tx: TransactionQuery) => Promise<T>): Promise<T>;
  close(): Promise<void>;
  /** POC only. Captured by this process, serialized with every query and transaction. */
  snapshotLocal?: () => Promise<Blob>;
}
export class TransactionCommitUnknownError extends Error {
  readonly outcome = "unknown";
  readonly retryAllowed = false;
  constructor() {
    super("Database commit outcome is unknown; reconcile current state before further action");
    this.name = "TransactionCommitUnknownError";
  }
}
export class TransactionAbortedError extends Error {
  constructor() {
    super("Database transaction was rolled back instead of committed");
    this.name = "TransactionAbortedError";
  }
}
function transactionQuery(execute: TransactionQuery["query"]) {
  let active = true;
  const handle: TransactionQuery = {
    async query(sql, params) {
      if (!active) throw new Error("Transaction callback has closed");
      return execute(sql, params);
    },
  };
  return {
    handle,
    close: () => {
      active = false;
    },
  };
}
async function bounded<T>(work: Promise<T>, stage: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`Database ${stage} deadline expired`)), 5000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
function provedCommitRejection(error: unknown): boolean {
  return error instanceof pg.DatabaseError && error.severity === "ERROR" && error.code === "23503";
}
export async function openDatabase(url: string, localPath?: string): Promise<Database> {
  if (url === "local") {
    const db = new PGlite(localPath);
    await db.waitReady;
    // PGlite 0.5.9's dumpDataDir does not acquire its query/transaction mutexes.
    // Keep the entire transaction and checkpoint/archive under our own gate.
    let tail: Promise<unknown> = Promise.resolve();
    function exclusive<T>(work: () => Promise<T>): Promise<T> {
      const result = tail.then(work);
      tail = result.catch(() => {});
      return result;
    }
    return {
      async query<T extends Record<string, unknown>>(sql: string, params: unknown[] = []) {
        return exclusive(async () => (await db.query<T>(sql, params)).rows);
      },
      transaction: (work) =>
        exclusive(() =>
          db.transaction(async (tx) => {
            const capability = transactionQuery(
              async <T extends Record<string, unknown>>(sql: string, params: unknown[] = []) =>
                (await tx.query<T>(sql, params)).rows,
            );
            try {
              return await work(capability.handle);
            } finally {
              capability.close();
            }
          }),
        ),
      snapshotLocal: () =>
        exclusive(async () => {
          await db.query("CHECKPOINT");
          await db.syncToFs();
          return db.dumpDataDir("gzip");
        }),
      close: () => exclusive(() => db.close()),
    };
  }
  const pool = new pg.Pool({
    connectionString: url,
    max: 20,
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30_000,
    statement_timeout: 10_000,
    query_timeout: 10_000,
  });
  pool.on("error", () => {
    try {
      process.stderr.write("PostgreSQL idle connection error\n");
    } catch {}
  });
  let state: "open" | "broken" | "closing" | "closed" = "open";
  let closing: Promise<void> | undefined;
  function admit() {
    if (state !== "open") throw new Error("Database handle is unavailable; explicitly open a new handle");
  }
  const diagnostic = (stage: "rollback" | "release" | "end") => {
    try {
      process.stderr.write(`PostgreSQL transaction cleanup failed (${stage})\n`);
    } catch {}
  };
  return {
    async query<T extends Record<string, unknown>>(sql: string, params: unknown[] = []) {
      admit();
      return (await pool.query<T>(sql, params)).rows;
    },
    async transaction(work) {
      admit();
      const client = await pool.connect();
      let phase: "begin" | "configure" | "work" | "commit" | "committed" = "begin";
      let disposition: "healthy" | "destroy" = "destroy";
      let transportFault = false;
      const fault = () => {
        transportFault = true;
      };
      client.on("error", fault);
      const capability = transactionQuery(async (sql, params = []) => (await client.query(sql, params)).rows);
      async function rollback() {
        try {
          const result = await bounded(client.query("ROLLBACK"), "rollback");
          if (result.command === "ROLLBACK" && !transportFault) disposition = "healthy";
        } catch {
          diagnostic("rollback");
        }
      }
      try {
        admit();
        await client.query("BEGIN");
        phase = "configure";
        await client.query("SET LOCAL lock_timeout = '5s'");
        phase = "work";
        const result = await work(capability.handle);
        capability.close();
        phase = "commit";
        const commit = await client.query("COMMIT");
        if (commit.command === "ROLLBACK") {
          disposition = transportFault ? "destroy" : "healthy";
          throw new TransactionAbortedError();
        }
        if (commit.command !== "COMMIT") throw new Error("Unexpected transaction completion");
        phase = "committed";
        disposition = transportFault ? "destroy" : "healthy";
        return result;
      } catch (error) {
        capability.close();
        if (phase === "commit") {
          if (error instanceof TransactionAbortedError) throw error;
          if (!provedCommitRejection(error)) throw new TransactionCommitUnknownError();
          await rollback();
        } else if (phase !== "begin") {
          await rollback();
        }
        throw error;
      } finally {
        capability.close();
        try {
          client.release(disposition === "destroy");
        } catch {
          state = "broken";
          diagnostic("release");
          try {
            await bounded(client.end(), "client close");
          } catch {
            diagnostic("end");
          }
        } finally {
          client.removeListener("error", fault);
        }
      }
    },
    close() {
      closing ??= (async () => {
        state = "closing";
        try {
          await bounded(pool.end(), "pool close");
          state = "closed";
        } catch (error) {
          state = "broken";
          throw error;
        }
      })();
      return closing;
    },
  };
}
export async function migrate(db: Database): Promise<void> {
  await migrateOrdered(db);
}
