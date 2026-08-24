import { mkdir } from "node:fs/promises";

import { defineConfig, presets, task } from "@xevion/tempo";

/// The tools read `.env` themselves: tempo execs under node, which ignores it; `bun run` does not.
const BUN = { tool: "bun", hint: "https://bun.sh — the corpus and secrets tools run under it" };

export default defineConfig({
  tasks: [
    ...presets.rust({
      name: "rust",
      override: {
        lint: "cargo clippy --workspace --all-targets --all-features -- -D warnings",
        // nextest skips doctests, so they run as a second pass rather than being lost.
        test:
          "cargo nextest run --workspace --all-features && " +
          "cargo test --workspace --all-features --doc",
        build: false,
      },
    }),

    // Building the docs is what fires the workspace's rustdoc lints.
    task({
      name: "rust:doc",
      body: "cargo doc --workspace --all-features --no-deps",
      tags: ["check"],
    }),

    // Out of `check`: advisories move without the tree moving, so CI runs them on a schedule.
    task({
      name: "ci:advisories",
      body: "cargo audit",
      requires: [{ tool: "cargo-audit", hint: "cargo install cargo-audit" }],
    }),

    task({
      name: "ci:workflows",
      // The pin audits silently skip without a token, so a local run borrows gh's.
      body: async (ctx) => {
        let token = process.env.GH_TOKEN;
        if (!token) {
          const { stdout, code } = await ctx.capture(["gh", "auth", "token"]);
          if (code !== 0) ctx.fail("no GH_TOKEN, and gh is not logged in");
          token = stdout.trim();
        }
        return ctx.run(["zizmor", "."], { env: { GH_TOKEN: token } });
      },
      tags: ["check"],
      always: true,
      requires: [{ tool: "zizmor" }, { tool: "gh", hint: "zizmor needs a token to resolve pins" }],
    }),

    // Advisory, and slow enough that it is not part of `check`.
    task({
      name: "rust:coverage",
      body: async (ctx) => {
        await mkdir("coverage", { recursive: true });
        const html = await ctx.run([
          "cargo", "llvm-cov", "nextest",
          "--workspace", "--all-features", "--no-fail-fast",
          "--html", "--output-dir", "coverage",
        ]);
        if (html !== 0) return html;
        return ctx.run([
          "cargo", "llvm-cov", "report", "--lcov", "--output-path", "coverage/lcov.info",
        ]);
      },
      requires: [{ tool: "cargo-llvm-cov" }],
    }),

    task({
      name: "corpus:cli",
      body: ["bun", "run", "tools/corpus.ts"],
      passthrough: true,
      requires: [BUN],
    }),

    task({
      name: "secrets:cli",
      body: ["bun", "run", "tools/secrets.ts"],
      passthrough: true,
      requires: [BUN, { tool: "gh" }],
    }),
  ],

  commands: {
    check: { description: "Format, lint, docs, tests, advisories, workflows", tags: ["check"] },
    fmt: { description: "Rewrite formatting in place", tags: ["format"], concurrency: 1 },
    coverage: { description: "Line coverage into coverage/", tasks: ["rust:coverage"] },
    audit: { description: "Scan dependencies for advisories", tasks: ["ci:advisories"] },
    corpus: {
      description: "Manage the sample corpus (status, pull, push, add, verify, prune)",
      tasks: ["corpus:cli"],
      passthrough: true,
    },
    secrets: {
      description: "Push .env values to GitHub Actions secrets (status, sync)",
      tasks: ["secrets:cli"],
      passthrough: true,
    },
  },
});
