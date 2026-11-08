// The spec lives in spec/ as one file per section. The site publishes it as
// one page, and as one Markdown file to download: spec/README.md first,
// then the other files in name order (01-… to 16-…, then the appendices),
// as its contents list them.

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

// Found from the site's folder, where npm runs, so that the path holds
// wherever the build puts compiled code.
export const SPEC_DIR = path.resolve(process.cwd(), "../spec") + path.sep;
export const SPEC_README_URL = pathToFileURL(path.join(SPEC_DIR, "README.md"));

/** The spec's file names, in reading order. */
export function specFiles(): string[] {
  return fs
    .readdirSync(SPEC_DIR)
    .filter((name) => name.endsWith(".md"))
    .sort((a, b) => Number(b === "README.md") - Number(a === "README.md") || a.localeCompare(b));
}

/** The whole spec as one Markdown text. */
export function stitchSpec(): string {
  return specFiles()
    .map((name) => fs.readFileSync(path.join(SPEC_DIR, name), "utf8").trimEnd() + "\n")
    .join("\n");
}

/** A heading's id, as the Markdown processor makes it (GitHub's rules). */
export function slug(heading: string): string {
  return heading
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s_-]/gu, "")
    .replace(/\s/g, "-");
}

/**
 * The id of the first section heading in a spec file, so that a link to
 * the file can point at its place on the one page. Empty for README.md,
 * which is the top of the page.
 */
export function specAnchor(name: string): string {
  if (name === "README.md") return "";
  const text = fs.readFileSync(path.join(SPEC_DIR, name), "utf8");
  const heading = text.match(/^## (.+)$/m)?.[1];
  return heading ? slug(heading) : "";
}
