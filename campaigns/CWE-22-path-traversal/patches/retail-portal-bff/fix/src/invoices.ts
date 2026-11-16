import { readFileSync } from "node:fs";
import path from "node:path";

// Returns a customer invoice PDF stored under baseDir.
export function readInvoice(baseDir: string, name: string): Buffer {
  const root = path.resolve(baseDir);
  const target = path.resolve(root, name);
  if (!target.startsWith(root + path.sep)) {
    throw new Error("invoice path escapes store");
  }
  return readFileSync(target);
}
