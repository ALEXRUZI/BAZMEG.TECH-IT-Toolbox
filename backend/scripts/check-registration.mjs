import { execFileSync } from "node:child_process";
import { readdirSync } from "node:fs";

for (const file of ["src/registration-route.mjs", ...readdirSync("src/tools").filter((name) => name.startsWith("registration-") && name.endsWith(".mjs")).map((name) => `src/tools/${name}`), "test/registration.test.mjs", "scripts/check-registration.mjs"]) {
  execFileSync(process.execPath, ["--check", file], { stdio: "inherit" });
}
