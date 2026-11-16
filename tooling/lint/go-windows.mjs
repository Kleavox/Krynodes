import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const cwd = fileURLToPath(new URL("../../agent/windows", import.meta.url));
const native = { ...process.env, GOWORK: "off" };
const windows = { ...native, GOOS: "windows", GOARCH: "amd64" };

const steps = [
  [["vet", "./..."], windows],
  [["build", "-buildvcs=false", "-o", "../../bin/", "./..."], windows],
  [["test", "./..."], native],
];

try {
  for (const [args, env] of steps) {
    process.stdout.write(`go -C agent/windows ${args.join(" ")}\n`);
    execFileSync("go", args, { cwd, env, stdio: "inherit" });
  }
} catch {
  process.stderr.write("\nwindows module check failed\n");
  process.exit(1);
}

process.stdout.write("Windows module: clean\n");
