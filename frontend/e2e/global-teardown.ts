import { rmSync, rmdirSync } from "node:fs";
import path from "node:path";
import { authStatePath } from "./auth-state";

export default function globalTeardown() {
  if (process.env.PLAYWRIGHT_AUTH_SETUP === "1") {
    rmSync(authStatePath, { force: true });
    // A configured directory may contain other runs' artifacts. Remove only our
    // state file, and remove the directory only when it is empty.
    try {
      rmdirSync(path.dirname(authStatePath));
    } catch (error) {
      if (!["ENOENT", "ENOTEMPTY"].includes((error as { code?: string }).code ?? "")) throw error;
    }
  }
}
