// Playwright global setup: re-seeds the test DB so specs that mutate finding state
// (suppress, accept-risk) don't leak into other specs in the same run.
//
// Uses spawnSync (not exec) with a static argv to avoid shell interpolation, no user input.
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

const SEED_ENV = process.env.CONSTELLATION_SEED_DB ?? "1";
const DB_URL = process.env.DATABASE_URL ??
  "postgres://test:test@localhost:15433/constellation_test?sslmode=disable";

async function globalSetup() {
  if (SEED_ENV !== "1") {
    console.log("[playwright global-setup] CONSTELLATION_SEED_DB=0 — skipping reseed");
    return;
  }
  const cwd = path.resolve(here, "..", "..");
  const res = spawnSync("go", ["run", "./cmd/constellation-seed"], {
    cwd,
    env: { ...process.env, DATABASE_URL: DB_URL },
    stdio: "pipe",
    timeout: 60_000,
  });
  if (res.status === 0) {
    console.log("[playwright global-setup] reseeded test DB");
    return;
  }
  console.warn(
    "[playwright global-setup] reseed failed; tests may be order-dependent:",
    res.stderr?.toString().trim(),
  );
}

export default globalSetup;
