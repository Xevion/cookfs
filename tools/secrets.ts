#!/usr/bin/env bun
//! Pushes local credentials to GitHub Actions secrets. Values are never printed, and reach
//! `gh secret set` over stdin rather than a command line `ps` could read.

/// Every secret a workflow reads. A name `.env` does not define is reported, not skipped.
const WANTED = [
  "CODECOV_TOKEN",
  "S3_ENDPOINT",
  "S3_BUCKET",
  "S3_ACCESS_KEY_ID",
  "S3_SECRET_ACCESS_KEY",
  "CARGO_REGISTRY_TOKEN",
] as const;

function die(message: string): never {
  console.error(`secrets: ${message}`);
  process.exit(1);
}

async function gh(args: string[], stdin?: string): Promise<string> {
  const proc = Bun.spawn(["gh", ...args], {
    stdin: stdin === undefined ? "ignore" : new TextEncoder().encode(stdin),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [out, err, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  if (code !== 0) die(`gh ${args[0]} ${args[1] ?? ""} failed: ${err.trim()}`);
  return out;
}

/// Names and update times only: GitHub never discloses a value, so presence is all there is.
async function remote(): Promise<Map<string, string>> {
  const json = await gh(["secret", "list", "--json", "name,updatedAt"]);
  const rows = JSON.parse(json) as { name: string; updatedAt: string }[];
  return new Map(rows.map((r) => [r.name, r.updatedAt.slice(0, 10)]));
}

async function status(): Promise<void> {
  const have = await remote();
  for (const name of WANTED) {
    const local = process.env[name] ? "in .env" : "MISSING";
    const there = have.get(name);
    console.log(`  ${name.padEnd(22)} ${local.padEnd(8)} ${there ? `set ${there}` : "not set"}`);
  }
  const extra = [...have.keys()].filter((n) => !WANTED.includes(n as (typeof WANTED)[number]));
  for (const name of extra) console.log(`  ${name.padEnd(22)} ${"".padEnd(8)} set, not in .env`);
}

async function sync(args: string[]): Promise<void> {
  const missing = WANTED.filter((name) => !process.env[name]);
  if (missing.length > 0 && !args.includes("--partial")) {
    die(`.env does not define ${missing.join(", ")} (pass --partial to push the rest)`);
  }

  const present = WANTED.filter((name) => process.env[name]);
  if (args.includes("--dry-run")) {
    for (const name of present) console.log(`  would set ${name}`);
    return;
  }

  for (const name of present) {
    await gh(["secret", "set", name], process.env[name]);
    console.log(`  set ${name}`);
  }
  console.log(`pushed ${present.length} secrets`);
}

const USAGE = `secrets <command>

  status                    compare .env against the repository's secrets
  sync [--dry-run]          push every .env value to GitHub  [--partial allows gaps]`;

const [command = "status", ...rest] = process.argv.slice(2);
switch (command) {
  case "status":
    await status();
    break;
  case "sync":
    await sync(rest);
    break;
  default:
    console.log(USAGE);
    process.exit(command === "help" || command === "--help" ? 0 : 1);
}
