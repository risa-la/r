import path from "node:path";
import { fileURLToPath } from "node:url";
import { REPO_URL, docId } from "../docs";

// Documents link to each other by file path (`../../PLAN.md#4-milestones`).
// Point those links at the site's pages, and any other repository file at
// its source on GitHub.

const repoRoot = fileURLToPath(new URL("../../../", import.meta.url));
const published = /^SPEC\.md$/;

export function siteUrl(href: string, fileURL: URL | undefined): string | undefined {
  if (!fileURL || /^([a-z]+:|#|\/)/i.test(href)) return;
  const [target, hash] = href.split("#");
  const file = path.resolve(path.dirname(fileURLToPath(fileURL)), target);
  const rel = path.relative(repoRoot, file).split(path.sep).join("/");
  if (rel.startsWith("..")) return;
  const suffix = hash ? `#${hash}` : "";
  return published.test(rel)
    ? `/${docId(rel)}/${suffix}`
    : `${REPO_URL}/blob/main/${rel}${suffix}`;
}

type Ctx = {
  fileURL: URL | undefined;
  setProperty(node: object, key: "url", value: string): void;
};

function rewrite(node: { url: string }, ctx: Ctx) {
  const url = siteUrl(node.url, ctx.fileURL);
  if (url) ctx.setProperty(node, "url", url);
}

export const docLinks = {
  name: "risala-doc-links",
  link: rewrite,
  definition: rewrite,
};
