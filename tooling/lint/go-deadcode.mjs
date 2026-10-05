import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const cwd = fileURLToPath(new URL("../../agent", import.meta.url));

let output = "";
try {
  output = execFileSync(
    "go",
    [
      "run",
      "golang.org/x/tools/cmd/deadcode@latest",
      "-filter",
      "^github.com/Kleavox/krynodes/agent/(cmd|internal)/[a-z]+$",
      "./...",
    ],
    { cwd, encoding: "utf8" },
  );
} catch (error) {
  process.stderr.write(error.stdout ?? "");
  process.stderr.write(error.stderr ?? "");
  process.stderr.write("\ndeadcode failed to run\n");
  process.exit(1);
}

if (output.trim()) {
  process.stderr.write("Dead Go code found:\n" + output + "\n");
  process.exit(1);
}

process.stdout.write("Go deadcode: clean\n");
