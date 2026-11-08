// The documents the site publishes. They stay where they are in the
// repository; the site reads them from there.

export const REPO_URL = "https://github.com/risa-la/r";

/** Paths relative to the repository root. */
export const DOC_PATTERNS = ["SPEC.md"];

/** Documents listed first, in this order; the rest follow by id. */
const PINNED = ["spec"];

/** Titles that differ from the document's first heading. */
const TITLES: Record<string, string> = {
  spec: "A Line-Based Chat Protocol",
};

/** `SPEC.md` is `spec`; a file under `docs/` drops that prefix. */
export function docId(file: string): string {
  return file
    .replace(/^docs\//, "")
    .replace(/\.md$/, "")
    .toLowerCase();
}

export function docOrder(a: string, b: string): number {
  const rank = (id: string) => {
    const i = PINNED.indexOf(id);
    return i === -1 ? PINNED.length : i;
  };
  return rank(a) - rank(b) || a.localeCompare(b);
}

export function docTitle(id: string, body: string | undefined): string {
  return TITLES[id] ?? body?.match(/^# (.+)$/m)?.[1].replaceAll("`", "") ?? id;
}

/** The spec's draft number, from the header block at its top. */
export function docVersion(body: string | undefined): string | undefined {
  return body?.match(/^risala\s+(draft-\d+)\s*$/m)?.[1];
}
