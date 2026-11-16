import { readFileSync } from "node:fs";
import path from "node:path";

// Naive fix (what a quick auto-fix might do): drop every directory component.
export function readInvoice(baseDir: string, name: string): Buffer {
  const safe = path.basename(name);
  if (safe !== name) {
    throw new Error("invoice path escapes store");
  }
  return readFileSync(path.join(baseDir, safe)); // cwe22-safe: basename only
}
