import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { readInvoice } from "../src/invoices.ts";

// CWE-22: invoice names from the request must not escape baseDir.
test("rejects traversal and absolute paths", () => {
  const root = mkdtempSync(path.join(tmpdir(), "inv-root-"));
  const base = path.join(root, "store");
  mkdirSync(base);
  const secret = path.join(root, "secret.txt");
  writeFileSync(secret, "stripe-key");
  for (const attack of ["../secret.txt", "2026/../../secret.txt", secret]) {
    assert.throws(() => readInvoice(base, attack), /escapes store/, attack);
  }
});
