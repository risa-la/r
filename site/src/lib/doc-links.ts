import path from "node:path";
import { fileURLToPath } from "node:url";
import { REPO_URL } from "../docs";
import { specAnchor } from "../spec";

// Documents link to each other by file path (`../../PLAN.md#4-milestones`).
// Point links into spec/ at their place on the spec's one page, and any
// other repository file at its source on GitHub.

const repoRoot = fileURLToPath(new URL("../../../", import.meta.url));
const specFile = /^spec\/([^/]+\.md)$/;

export function siteUrl(href: string, fileURL: URL | undefined): string | undefined {
  if (!fileURL || /^([a-z]+:|#|\/)/i.test(href)) return;
  const [target, hash] = href.split("#");
  const file = path.resolve(path.dirname(fileURLToPath(fileURL)), target);
  const rel = path.relative(repoRoot, file).split(path.sep).join("/");
  if (rel.startsWith("..")) return;
  const spec = rel.match(specFile);
  if (spec) {
    const anchor = hash || specAnchor(spec[1]);
    return anchor ? `/spec/#${anchor}` : "/spec/";
  }
  return `${REPO_URL}/blob/main/${rel}${hash ? `#${hash}` : ""}`;
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
