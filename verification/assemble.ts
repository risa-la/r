// Turns the raw results of collect.sh into the data the verification page
// reads: one JSON file per source file (its text and, per line, what
// reaches it), a summary, and the spec view.
//
//   node verification/assemble.ts [--root DIR] [--raw DIR] [--out DIR]
//
// --root  the checkout whose sources were verified (default: this one)
// --raw   collect.sh's results (default: <root>/target/verification/raw)
// --out   where to write (default: site/public/verification-data)
//
// VERIFY_ROOT, VERIFY_RAW and VERIFY_OUT set the same, for npm scripts.
//
// Any part of --raw may be missing: that kind of evidence is then marked
// as having no results, and the page says so.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  type LineCounts,
  lineCountsFromSegments,
  type Segment,
  testRanges,
  citationsIn,
  sectionsInComment,
  expandSections,
  parseTlc,
  specSections,
  specExamples,
  xccovLines,
  normalisePath,
  docAbove,
  type Section,
} from "./lib.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));

// Arguments ------------------------------------------------------------------

function arg(name: string, env: string, fallback: string): string {
  const i = process.argv.indexOf(name);
  if (i !== -1) return path.resolve(process.argv[i + 1]);
  return process.env[env] ? path.resolve(process.env[env]!) : fallback;
}

const ROOT = arg("--root", "VERIFY_ROOT", path.resolve(HERE, ".."));
const RAW = arg("--raw", "VERIFY_RAW", path.join(ROOT, "target/verification/raw"));
const OUT = arg("--out", "VERIFY_OUT", path.resolve(HERE, "../site/public/verification-data"));
// The checkout this script is in, for git: the draft the code cites.
const REPO = path.resolve(HERE, "..");

const config = JSON.parse(fs.readFileSync(path.join(HERE, "config.json"), "utf8"));

function readJson(file: string): any | undefined {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return undefined;
  }
}

function readText(file: string): string | undefined {
  try {
    return fs.readFileSync(file, "utf8");
  } catch {
    return undefined;
  }
}

// Sources --------------------------------------------------------------------

type Lang = "rust" | "swift";

interface SourceFile {
  path: string; // relative to ROOT, with forward slashes
  lang: Lang;
  crate: string; // the crate, or "apple" for the Swift client
  text: string;
  lines: string[];
  test: boolean; // the whole file is test code
  testRanges: [number, number][]; // test code inside it, 1-based, inclusive
}

function walk(dir: string, ext: string, exclude: string[], out: string[]) {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    const rel = path.relative(ROOT, full).split(path.sep).join("/");
    if (exclude.some((x) => (x.startsWith("/") ? `/${rel}/`.includes(x) : rel.startsWith(x)))) continue;
    if (e.isDirectory()) walk(full, ext, exclude, out);
    else if (e.isFile() && e.name.endsWith(ext)) out.push(rel);
  }
}

function crateOf(rel: string, lang: Lang): string {
  if (lang === "swift") return "apple";
  return rel.split("/")[1];
}

/** Files that a `#[cfg(test)]` or `#[cfg(kani)]` module declaration pulls in. */
function testModuleFiles(files: Map<string, SourceFile>): Set<string> {
  const found = new Set<string>();
  for (const f of files.values()) {
    if (f.lang !== "rust") continue;
    const re = /#\[cfg\((?:test|kani)\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;/g;
    for (const m of f.text.matchAll(re)) {
      const name = m[1];
      const dir = path.posix.dirname(f.path);
      const base = path.posix.basename(f.path, ".rs");
      // A module declared in mod.rs, lib.rs or main.rs sits beside it;
      // one declared in foo.rs sits in foo/.
      const parent = ["mod", "lib", "main"].includes(base) ? dir : `${dir}/${base}`;
      for (const cand of [`${parent}/${name}.rs`, `${parent}/${name}/mod.rs`]) {
        if (files.has(cand)) found.add(cand);
      }
    }
  }
  return found;
}

function isTestPath(rel: string, lang: Lang): boolean {
  if (lang === "swift") return /\/Tests\//.test(`/${rel}`);
  return /\/(tests|fuzz|benches|examples)\//.test(`/${rel}`) || /\/proofs\.rs$/.test(rel);
}

function loadSources(): Map<string, SourceFile> {
  const files = new Map<string, SourceFile>();
  for (const [lang, src] of Object.entries(config.sources) as [Lang, any][]) {
    const rels: string[] = [];
    walk(path.join(ROOT, src.root), src.extension, src.exclude, rels);
    for (const rel of rels.sort()) {
      const text = fs.readFileSync(path.join(ROOT, rel), "utf8");
      const lines = text.split("\n");
      if (lines.at(-1) === "") lines.pop();
      files.set(rel, {
        path: rel,
        lang,
        crate: crateOf(rel, lang),
        text,
        lines,
        test: isTestPath(rel, lang),
        testRanges: lang === "rust" ? testRanges(lines) : [],
      });
    }
  }
  // Files that are test modules nested in src/, and files whose module
  // is itself a test module, are test code too.
  for (let changed = true; changed; ) {
    changed = false;
    for (const rel of testModuleFiles(files)) {
      const f = files.get(rel)!;
      if (!f.test) {
        f.test = true;
        changed = true;
      }
    }
  }
  return files;
}

const sources = loadSources();

function isTestLine(f: SourceFile, line: number): boolean {
  return f.test || f.testRanges.some(([a, b]) => line >= a && line <= b);
}

// Coverage from llvm-cov -----------------------------------------------------

interface FnSpan {
  name: string;
  path: string;
  start: number;
  end: number;
}

/** Per file, per line, the count, from an llvm-cov export. */
function llvmCov(file: string, fns?: FnSpan[]): Map<string, LineCounts> | undefined {
  const json = readJson(file);
  if (!json) return undefined;
  const result = new Map<string, LineCounts>();
  for (const data of json.data ?? []) {
    for (const f of data.files ?? []) {
      const rel = normalisePath(f.filename, ROOT);
      if (!rel || !sources.has(rel)) continue;
      const counts = lineCountsFromSegments(f.segments as Segment[]);
      const prev = result.get(rel);
      if (prev) for (const [l, c] of counts) prev.set(l, Math.max(prev.get(l) ?? 0, c));
      else result.set(rel, counts);
    }
    if (fns) {
      for (const fn of data.functions ?? []) {
        const rel = normalisePath(fn.filenames?.[0] ?? "", ROOT);
        if (!rel || !sources.has(rel)) continue;
        // Regions in the function's own file (file id 0), not expansions.
        let start = Infinity;
        let end = -Infinity;
        for (const r of fn.regions as number[][]) {
          if (r[5] !== 0) continue;
          start = Math.min(start, r[0]);
          end = Math.max(end, r[2]);
        }
        if (start <= end) fns.push({ name: fn.name, path: rel, start, end });
      }
    }
  }
  return result;
}

const functions: FnSpan[] = [];
const unit = llvmCov(path.join(RAW, "tests/unit.json"), functions);
const integration = llvmCov(path.join(RAW, "tests/integration.json"), functions);
const unitStatus = readJson(path.join(RAW, "tests/unit-status.json"));
const integrationStatus = readJson(path.join(RAW, "tests/integration-status.json"));

// One span per function, generic copies merged.
const fnSpans = (() => {
  const seen = new Map<string, FnSpan>();
  for (const f of functions) {
    const key = `${f.path}:${f.start}`;
    const prev = seen.get(key);
    if (!prev || f.end > prev.end) seen.set(key, f);
  }
  return [...seen.values()];
})();

// The Swift client, from xccov -----------------------------------------------

const swiftRaw = readJson(path.join(RAW, "swift/xccov.json"));
const swiftStatus = readJson(path.join(RAW, "swift/status.json"));
const swift = swiftRaw ? xccovLines(swiftRaw, (p) => normalisePath(p, ROOT)) : undefined;
if (swift) for (const rel of [...swift.keys()]) if (!sources.has(rel)) swift.delete(rel);

// Fuzzing --------------------------------------------------------------------

interface FuzzTarget {
  crate: string;
  target: string;
  inputs?: number;
  seconds?: number;
  runs?: number;
  last?: string;
  hasCoverage: boolean;
}

const fuzzTargets: FuzzTarget[] = [];
// Per file, per line, the indexes of the targets that reach it.
const fuzzHits = new Map<string, Map<number, number[]>>();
const fuzzInstrumented = new Map<string, Set<number>>();
let fuzzAny = false;
for (const [crate, targets] of Object.entries(config.fuzz) as [string, string[]][]) {
  const stats = readJson(path.join(RAW, `fuzz/${crate}.stats.json`)) ?? {};
  for (const target of targets) {
    const meta = readJson(path.join(RAW, `fuzz/${crate}.${target}.meta.json`));
    const cov = llvmCov(path.join(RAW, `fuzz/${crate}.${target}.json`));
    const index = fuzzTargets.length;
    fuzzTargets.push({
      crate,
      target,
      inputs: meta?.inputs,
      seconds: stats[target]?.seconds,
      runs: stats[target]?.runs,
      last: stats[target]?.last,
      hasCoverage: !!cov,
    });
    if (!cov) continue;
    fuzzAny = true;
    for (const [rel, counts] of cov) {
      const hits = fuzzHits.get(rel) ?? new Map();
      fuzzHits.set(rel, hits);
      const inst = fuzzInstrumented.get(rel) ?? new Set();
      fuzzInstrumented.set(rel, inst);
      for (const [line, count] of counts) {
        inst.add(line);
        if (count > 0) hits.set(line, [...(hits.get(line) ?? []), index]);
      }
    }
  }
}

// Kani -----------------------------------------------------------------------

interface Harness {
  id: string;
  crate: string;
  path: string;
  line: number;
  endLine: number;
  status: string; // "success", "failure", "timeout" or "unknown"
  durationMs?: number;
  doc: string;
  sections: string[];
  coverage: "line" | "function" | "none";
}

const harnesses: Harness[] = [];
const kaniHits = new Map<string, Map<number, number[]>>();
const kaniMissed = new Map<string, Map<number, number[]>>();
let kaniAny = false;

function addHit(map: Map<string, Map<number, number[]>>, rel: string, line: number, index: number) {
  const m = map.get(rel) ?? new Map<number, number[]>();
  map.set(rel, m);
  const list = m.get(line) ?? [];
  if (!list.includes(index)) list.push(index);
  m.set(line, list);
}

/** Functions a harness calls, by name, for when Kani gives no coverage. */
function calledFunctions(h: Harness): FnSpan[] {
  const f = sources.get(h.path);
  if (!f) return [];
  const body = f.lines.slice(h.line - 1, h.endLine).join("\n");
  const names = new Set([...body.matchAll(/([A-Za-z_][A-Za-z0-9_]*)\s*(?:::<[^>]*>)?\s*\(/g)].map((m) => m[1]));
  return fnSpans.filter((fn) => {
    if (crateOf(fn.path, "rust") !== h.crate || fn.path === h.path) return false;
    const last = fn.name.replace(/<[^>]*>/g, "").split("::").at(-1) ?? "";
    return names.has(last);
  });
}

for (const crate of config.kani as string[]) {
  const json = readJson(path.join(RAW, `kani/${crate}.json`));
  if (!json) continue;
  kaniAny = true;
  const covDir = path.join(RAW, `kani/${crate}.coverage`);
  const covFiles = (() => {
    try {
      return fs.readdirSync(covDir);
    } catch {
      return [];
    }
  })();
  const results = new Map<string, any>((json.verification_results?.results ?? []).map((r: any) => [r.harness_id, r]));
  for (const meta of json.harness_metadata ?? []) {
    const rel = normalisePath(meta.source.file, ROOT) ?? meta.source.file;
    const r = results.get(meta.pretty_name);
    const raw = String(r?.status ?? "unknown").toLowerCase();
    const status = raw.includes("timeout") ? "timeout" : raw === "success" ? "success" : raw === "failure" ? "failure" : raw;
    const f = sources.get(rel);
    const doc = f ? docAbove(f.lines, meta.source.start_line) : "";
    const h: Harness = {
      id: meta.pretty_name,
      crate,
      path: rel,
      line: meta.source.start_line,
      endLine: meta.source.end_line,
      status,
      durationMs: r?.duration_ms,
      doc,
      sections: expandSections(sectionsInComment(doc)),
      coverage: "none",
    };
    const index = harnesses.length;
    harnesses.push(h);
    const covFile = covFiles.find((c) => c.startsWith(`${meta.mangled_name}_kaniraw`));
    const cov = covFile ? readJson(path.join(covDir, covFile)) : undefined;
    if (cov && status === "success") {
      h.coverage = "line";
      for (const [file, regions] of Object.entries(cov.data ?? {}) as [string, any[]][]) {
        const r = normalisePath(file, ROOT) ?? file;
        if (!sources.has(r)) continue;
        for (const region of regions) {
          const [a] = region.region.start;
          const [b] = region.region.end;
          const target = region.status === "COVERED" ? kaniHits : kaniMissed;
          for (let l = a; l <= b; l++) addHit(target, r, l, index);
        }
      }
    } else if (status === "success") {
      const called = calledFunctions(h);
      if (called.length) h.coverage = "function";
      for (const fn of called) for (let l = fn.start; l <= fn.end; l++) addHit(kaniHits, fn.path, l, index);
    }
  }
}

// TLA+ -----------------------------------------------------------------------

interface TlaRun {
  model: string;
  config: string;
  expect: string;
  meaning: string;
  result: string; // "pass", "violation", "stopped", "error" or "none"
  asExpected: boolean;
  invariant?: string;
  states?: number;
  distinct?: number;
  depth?: number;
  traceLength?: number;
  seconds?: number;
  limit?: number;
}

const tlaRuns: TlaRun[] = [];
let tlaAny = false;
for (const model of config.tla.models) {
  for (const run of model.runs) {
    const name = `${model.id}.${run.config.replace(/\.cfg$/, "")}`;
    const log = readText(path.join(RAW, `tla/${name}.log`));
    const status = readJson(path.join(RAW, `tla/${name}.status.json`));
    if (!log || !status) {
      tlaRuns.push({ model: model.id, config: run.config, expect: run.expect, meaning: run.meaning, result: "none", asExpected: false });
      continue;
    }
    tlaAny = true;
    const parsed = parseTlc(log, status.exit);
    tlaRuns.push({
      model: model.id,
      config: run.config,
      expect: run.expect,
      meaning: run.meaning,
      ...parsed,
      asExpected: parsed.result === run.expect,
      seconds: status.seconds,
      limit: status.limit,
    });
  }
}

// Spec citations and the spec view -------------------------------------------

/** Sections of the draft the code cites, from git. */
function codeDraftText(): string | undefined {
  try {
    return execFileSync("git", ["-C", REPO, "show", config.spec.code.git], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  } catch {
    return undefined;
  }
}

function publishedDraftText(): string {
  const dir = path.join(ROOT, config.spec.published.dir);
  const names = fs
    .readdirSync(dir)
    .filter((n) => n.endsWith(".md"))
    .sort((a, b) => Number(b === "README.md") - Number(a === "README.md") || a.localeCompare(b));
  return names.map((n) => fs.readFileSync(path.join(dir, n), "utf8").trimEnd() + "\n").join("\n");
}

const codeDraft = codeDraftText();
const codeSections = codeDraft ? specSections(codeDraft) : [];
const codeSectionIds = new Set(codeSections.map((s) => s.num));

// A proof's doc may name a section without parentheses ("the set of 2.3").
// Bare numbers count there, if they are sections of the draft the code
// cites.
for (const h of harnesses) {
  const bare = [...h.doc.matchAll(/(?<![\d.])\d{1,2}\.\d{1,2}(?![\d.]\d)/g)].map((m) => m[0]);
  const all = expandSections([...h.sections, ...bare]);
  h.sections = codeSectionIds.size ? all.filter((x) => codeSectionIds.has(x)) : h.sections;
}
const published = publishedDraftText();
const publishedSections = specSections(published);

// Every citation of a section in a comment, in non-test and test code.
interface Citation {
  section: string;
  path: string;
  line: number;
  test: boolean;
}
const citations: Citation[] = [];
for (const f of sources.values()) {
  if (f.lang !== "rust") continue;
  for (const c of citationsIn(f.lines)) {
    for (const section of expandSections(c.sections)) {
      if (codeSectionIds.size && !codeSectionIds.has(section)) continue;
      citations.push({ section, path: f.path, line: c.line, test: isTestLine(f, c.line) });
    }
  }
}

// The TLA+ column: lines of functions whose comments cite a section a
// model covers.
const tlaHits = new Map<string, Map<number, string[]>>();
const tlaSections = new Map<string, string[]>(); // section -> model ids
for (const model of config.tla.models) {
  for (const s of model.sections) tlaSections.set(s, [...(tlaSections.get(s) ?? []), model.id]);
}
if (tlaAny) {
  for (const fn of fnSpans) {
    const f = sources.get(fn.path)!;
    if (isTestLine(f, fn.start)) continue;
    // The comments above the function and inside it.
    let top = fn.start - 1;
    while (top >= 1 && /^\s*(\/\/|#\[|\*)/.test(f.lines[top - 1])) top--;
    const cited = new Set<string>();
    for (const c of citationsIn(f.lines.slice(top, fn.end), top)) {
      for (const s of expandSections(c.sections)) if (tlaSections.has(s)) cited.add(s);
    }
    if (!cited.size) continue;
    const m = tlaHits.get(fn.path) ?? new Map<number, string[]>();
    tlaHits.set(fn.path, m);
    const list = [...cited].sort();
    for (let l = fn.start; l <= fn.end; l++) m.set(l, list);
  }
}

// Per file -------------------------------------------------------------------

type Layer = "unit" | "integration" | "fuzz" | "kani" | "tla";
const LAYERS: Layer[] = ["unit", "integration", "fuzz", "kani", "tla"];

interface Tally {
  covered: number;
  total: number;
}
const zero = (): Tally => ({ covered: 0, total: 0 });
const tallies = () => Object.fromEntries([...LAYERS, "any"].map((l) => [l, zero()])) as Record<Layer | "any", Tally>;

fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(path.join(OUT, "files"), { recursive: true });

const fileIndex: any[] = [];
const crateTallies = new Map<string, Record<Layer | "any", Tally>>();
const totals = tallies();

for (const f of sources.values()) {
  const isSwift = f.lang === "swift";
  const u = isSwift ? swift?.get(f.path) : unit?.get(f.path);
  const i = isSwift ? undefined : integration?.get(f.path);
  const fz = fuzzHits.get(f.path);
  const fzi = fuzzInstrumented.get(f.path);
  const kh = kaniHits.get(f.path);
  const km = kaniMissed.get(f.path);
  const th = tlaHits.get(f.path);

  // Per line: [unit count, integration count, fuzz targets, kani harnesses
  // reached, kani harnesses that missed it, tla sections]. Lines that no
  // tool instruments are left out.
  const lines: Record<number, any> = {};
  const t = tallies();
  const hasCode = !!(u?.size || i?.size || fzi?.size);
  for (let n = 1; n <= f.lines.length; n++) {
    const uc = u?.get(n);
    const ic = i?.get(n);
    const fuzzT = fz?.get(n);
    const fuzzInst = fzi?.has(n);
    // Kani regions and whole functions span comments and blank lines:
    // keep their marks only on code, as llvm-cov sees it when it has
    // results for this file, or else on lines that are not blank or
    // comments.
    const isCode = hasCode ? uc !== undefined || ic !== undefined || !!fuzzInst : !/^\s*(\/\/.*)?$/.test(f.lines[n - 1]);
    const kani = isCode ? kh?.get(n) : undefined;
    const kmiss = isCode ? km?.get(n) : undefined;
    const tla = isCode ? th?.get(n) : undefined;
    const instrumented = uc !== undefined || ic !== undefined || !!fuzzInst;
    if (!instrumented && !kani && !kmiss && !tla) continue;
    const entry: any = {};
    if (uc !== undefined) entry.u = uc;
    if (ic !== undefined) entry.i = ic;
    if (fuzzT) entry.f = fuzzT;
    else if (fuzzInst) entry.f = [];
    if (kani) entry.k = kani;
    if (kmiss) entry.km = kmiss.filter((x) => !kani?.includes(x));
    if (tla) entry.t = tla;
    lines[n] = entry;

    // Percentages count lines that coverage instruments (tests or fuzzing),
    // outside test code.
    if (!instrumented || isTestLine(f, n)) continue;
    const hit = {
      unit: (uc ?? 0) > 0,
      integration: (ic ?? 0) > 0,
      fuzz: !!fuzzT?.length,
      kani: !!kani?.length,
      tla: !!tla?.length,
    };
    for (const l of LAYERS) {
      t[l].total++;
      if (hit[l]) t[l].covered++;
    }
    t.any.total++;
    if (hit.unit || hit.integration || hit.fuzz || hit.kani) t.any.covered++;
  }

  const out = {
    path: f.path,
    lang: f.lang,
    crate: f.crate,
    test: f.test,
    testRanges: f.testRanges,
    source: f.text,
    lines,
  };
  const dest = path.join(OUT, "files", `${f.path}.json`);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, JSON.stringify(out));

  fileIndex.push({ path: f.path, lang: f.lang, crate: f.crate, test: f.test, lines: f.lines.length, tally: t });
  const ct = crateTallies.get(f.crate) ?? tallies();
  crateTallies.set(f.crate, ct);
  for (const l of [...LAYERS, "any"] as const) {
    ct[l].covered += t[l].covered;
    ct[l].total += t[l].total;
    totals[l].covered += t[l].covered;
    totals[l].total += t[l].total;
  }
}

// The spec view --------------------------------------------------------------

function sectionView(sections: Section[], draft: string, withExamples: boolean, text: string) {
  const examples = withExamples ? specExamples(text) : new Map();
  return sections.map((s) => {
    const cites = draft === config.spec.code.draft ? citations.filter((c) => c.section === s.num) : [];
    const models = config.tla.models.filter((m: any) => m.draft === draft && m.sections.includes(s.num)).map((m: any) => m.id);
    const proofs = draft === config.spec.code.draft ? harnesses.flatMap((h, i) => (h.sections.includes(s.num) ? [i] : [])) : [];
    return {
      num: s.num,
      title: s.title,
      depth: s.depth,
      examples: examples.get(s.num) ?? { client: 0, server: 0 },
      code: cites.filter((c) => !c.test).map((c) => [c.path, c.line]),
      tests: cites.filter((c) => c.test).map((c) => [c.path, c.line]),
      tla: models,
      kani: proofs,
    };
  });
}

const spec = {
  codeDraft: config.spec.code.draft,
  codeNote: config.spec.code.note,
  drafts: [
    {
      id: config.spec.published.draft,
      published: true,
      sections: sectionView(publishedSections, config.spec.published.draft, true, published),
    },
    ...(codeDraft && config.spec.code.draft !== config.spec.published.draft
      ? [
          {
            id: config.spec.code.draft,
            published: false,
            sections: sectionView(codeSections, config.spec.code.draft, false, codeDraft),
          },
        ]
      : []),
  ],
};
fs.writeFileSync(path.join(OUT, "spec.json"), JSON.stringify(spec));

// The summary ----------------------------------------------------------------

const meta = readJson(path.join(RAW, "meta.json")) ?? {};
const summary = {
  commit: meta.commit ?? null,
  runUrl: meta.runUrl ?? null,
  generated: meta.generated ?? null,
  assembled: new Date().toISOString(),
  has: {
    unit: !!unit,
    integration: !!integration,
    fuzz: fuzzAny,
    kani: kaniAny,
    tla: tlaAny,
    swift: !!swift,
  },
  tests: { unit: unitStatus ?? null, integration: integrationStatus ?? null, swift: swiftStatus ?? null },
  fuzz: fuzzTargets,
  kani: harnesses,
  tla: {
    runs: tlaRuns,
    models: config.tla.models.map((m: any) => ({ id: m.id, title: m.title, file: m.file, readme: m.readme, draft: m.draft, summary: m.summary, sections: m.sections })),
  },
  totals,
  crates: [...crateTallies.entries()].sort().map(([name, tally]) => ({ name, tally })),
  files: fileIndex,
};
fs.writeFileSync(path.join(OUT, "summary.json"), JSON.stringify(summary));

const pct = (t: Tally) => (t.total ? `${((100 * t.covered) / t.total).toFixed(1)}%` : "-");
console.log(
  `verification data: ${fileIndex.length} files, ` +
    LAYERS.map((l) => `${l} ${pct(totals[l])}`).join(", ") +
    `, ${harnesses.length} Kani proofs, ${tlaRuns.filter((r) => r.result !== "none").length} TLC runs -> ${path.relative(process.cwd(), OUT)}`,
);
