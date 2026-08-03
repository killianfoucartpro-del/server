import { drizzle } from "drizzle-orm";

export async function initDb(databaseUrl?: string) {
  const url = databaseUrl ?? process.env.DATABASE_URL ?? "";
  if (!url) return null;

  const parsed = new URL(url);

  // Use dynamic imports so we only load the driver we need at runtime.
  if (parsed.protocol.startsWith("mysql")) {
    const { drizzle: mysqlDrizzle } = await import("drizzle-orm/mysql2");
    const { createPool } = await import("mysql2/promise");
    const pool = createPool({ uri: url });
    return mysqlDrizzle(pool);
  }

  if (parsed.protocol.startsWith("postgres") || parsed.protocol.startsWith("postgresql")) {
    // postgresjs adapter
    const { drizzle: pgDrizzle } = await import("drizzle-orm/postgres-js");
    const postgres = (await import("postgres")).default;
    const pg = postgres(url);
    return pgDrizzle(pg as any);
  }

  throw new Error("Unsupported DATABASE_URL protocol");
}
