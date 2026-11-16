import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { readInvoice } from "../src/invoices.ts";

test("reads a nested invoice", () => {
  const base = mkdtempSync(path.join(tmpdir(), "inv-"));
  mkdirSync(path.join(base, "2026", "11"), { recursive: true });
  writeFileSync(path.join(base, "2026", "11", "INV-77.pdf"), "pdf");
  assert.equal(readInvoice(base, "2026/11/INV-77.pdf").toString(), "pdf");
});

test("missing invoice throws ENOENT", () => {
  const base = mkdtempSync(path.join(tmpdir(), "inv-"));
  assert.throws(() => readInvoice(base, "none.pdf"), { code: "ENOENT" });
});
