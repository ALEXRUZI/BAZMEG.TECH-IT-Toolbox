import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

test("production deployment offline transaction, archive and workflow regressions", () => {
  execFileSync("python3", ["-B", "-m", "unittest", "discover", "-s", "deploy/tests", "-v"], {
    cwd: fileURLToPath(new URL("../../", import.meta.url)),
    timeout: 120_000,
    stdio: "inherit",
  });
});
