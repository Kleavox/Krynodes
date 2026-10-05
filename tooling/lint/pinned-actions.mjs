import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const workflows = fileURLToPath(
  new URL("../../.github/workflows", import.meta.url),
);

const loose = [];
for (const name of readdirSync(workflows).filter((file) =>
  /\.ya?ml$/.test(file),
)) {
  const lines = readFileSync(resolve(workflows, name), "utf8").split(/\r?\n/);
  if (!lines.includes("permissions:")) {
    loose.push(`  .github/workflows/${name} has no top-level permissions`);
  }
  lines.forEach((line, index) => {
    const used = line.match(/^\s*(?:-\s*)?uses:\s*([^\s#]+)/);
    if (used && !used[1].startsWith("./") && !/@[0-9a-f]{40}$/.test(used[1])) {
      loose.push(`  .github/workflows/${name}:${index + 1} ${used[1]}`);
    }
  });
}

if (loose.length > 0) {
  process.stderr.write(
    `Pin every action to a full commit SHA (a tag can be moved) and give every workflow top-level permissions:\n${loose.join("\n")}\n`,
  );
  process.exit(1);
}
console.log("Pinned actions: clean");
