import { readFileSync } from "node:fs";
import path from "node:path";

// Returns a customer invoice PDF stored under baseDir.
export function readInvoice(baseDir: string, name: string): Buffer {
  return readFileSync(path.join(baseDir, name));
}
