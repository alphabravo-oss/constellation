import { rmSync } from "node:fs";
import path from "node:path";
import { authStatePath } from "./auth-state";

export default function globalTeardown() {
  if (process.env.PLAYWRIGHT_AUTH_SETUP === "1") {
    rmSync(path.dirname(authStatePath), { recursive: true, force: true });
  }
}
