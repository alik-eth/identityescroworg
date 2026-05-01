// SPDX-License-Identifier: GPL-3.0-or-later
//
// Reproducibility gate for src/libs/PoseidonBytecode.sol.
//
// Re-runs `generate-poseidon-bytecode.ts --solidity` and asserts the
// produced output is byte-identical to the file currently committed at
// src/libs/PoseidonBytecode.sol. Without this, the source constants could
// silently drift from what the generator would produce — an auditor
// running the generator after a circomlib version bump or a copy-paste
// mishap would have no automated way to flag it.
//
// CI invocation:
//   pnpm --silent tsx packages/contracts/script/check-poseidon-reproducibility.ts
//
// Exit 0 ⇒ in sync. Exit 1 ⇒ drift; commit message includes the diff.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createHash } from "node:crypto";

const REPO_ROOT = resolve(__dirname, "../../..");
const GENERATOR = "packages/contracts/script/generate-poseidon-bytecode.ts";
const TARGET = "packages/contracts/src/libs/PoseidonBytecode.sol";

function sha256(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

function main() {
  const proc = spawnSync("pnpm", ["--silent", "tsx", GENERATOR, "--solidity"], {
    cwd: REPO_ROOT,
    stdio: ["ignore", "pipe", "inherit"],
    encoding: "buffer",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (proc.status !== 0) {
    console.error("generator exited non-zero:", proc.status);
    process.exit(1);
  }

  const generated: Buffer = proc.stdout;
  const onDisk = readFileSync(resolve(REPO_ROOT, TARGET));

  if (Buffer.compare(generated, onDisk) === 0) {
    console.log(
      `OK — PoseidonBytecode.sol matches generator output (${onDisk.length} bytes, sha256 ${sha256(onDisk)})`,
    );
    process.exit(0);
  }

  console.error("DRIFT — PoseidonBytecode.sol has diverged from generator output");
  console.error(`  on-disk:   ${onDisk.length} bytes, sha256 ${sha256(onDisk)}`);
  console.error(`  generated: ${generated.length} bytes, sha256 ${sha256(generated)}`);
  console.error("");
  console.error("  To resync, run:");
  console.error(
    `    pnpm --silent tsx ${GENERATOR} --solidity > ${TARGET}`,
  );
  process.exit(1);
}

main();
