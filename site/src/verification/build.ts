// Build-time access to the verification data, for pages rendered by Astro
// (the front page's numbers, and one shell page per source file). The
// browser reads the same files over HTTP; see data.ts.

import fs from "node:fs";
import path from "node:path";
import type { Summary } from "./types";

// Found from the site's folder, where npm runs, as spec.ts does.
const DATA_DIR = path.resolve(process.cwd(), "public/verification-data");

/** The summary, or undefined when assemble.ts has not run. */
export function readSummary(): Summary | undefined {
  try {
    return JSON.parse(fs.readFileSync(path.join(DATA_DIR, "summary.json"), "utf8"));
  } catch {
    return undefined;
  }
}
