// The parts of assemble.ts that read one tool's output, kept free of the
// file system so that lib.test.ts can test them.

/** Per line (1-based), how many times it ran. Lines not in the map are not code. */
export type LineCounts = Map<number, number>;

/** An llvm-cov segment: line, column, count, has count, region entry, gap. */
export type Segment = [number, number, number, boolean, boolean, boolean];

/**
 * Line counts from llvm-cov's segments, by the rule llvm-cov itself uses
 * for its line view (LineCoverageStats): a line is code if a region starts
 * on it, or a region with a count runs through it, and it does not start a
 * skipped region. Its count is the highest of those regions'.
 */
export function lineCountsFromSegments(segments: Segment[]): LineCounts {
  const counts: LineCounts = new Map();
  if (!segments.length) return counts;
  const isStart = (s: Segment) => !s[5] && s[3] && s[4];
  let i = 0;
  let wrapped: Segment | undefined;
  const last = segments[segments.length - 1][0];
  for (let line = segments[0][0]; line <= last; line++) {
    const onLine: Segment[] = [];
    while (i < segments.length && segments[i][0] === line) onLine.push(segments[i++]);
    const starts = onLine.filter(isStart);
    const skipped = onLine.length > 0 && !onLine[0][3] && onLine[0][4];
    const mapped = !skipped && ((wrapped !== undefined && wrapped[3]) || starts.length > 0);
    if (mapped) {
      let count = wrapped?.[3] ? wrapped[2] : 0;
      for (const s of starts) count = Math.max(count, s[2]);
      counts.set(line, count);
    }
    if (onLine.length) wrapped = onLine[onLine.length - 1];
  }
  return counts;
}

/**
 * The items under `#[cfg(test)]` or `#[cfg(kani)]` in a Rust file, as
 * 1-based inclusive line ranges, attribute included. Braces in strings,
 * characters and comments are skipped.
 */
export function testRanges(lines: string[]): [number, number][] {
  const ranges: [number, number][] = [];
  const text = lines.join("\n");
  const lineOf = (offset: number) => {
    let n = 1;
    for (let k = 0; k < offset; k++) if (text.charCodeAt(k) === 10) n++;
    return n;
  };
  const re = /^[ \t]*#\[cfg\((?:test|kani|all\(test[^\]]*|all\(kani[^\]]*)\)\]/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const start = m.index;
    const end = itemEnd(text, m.index + m[0].length);
    ranges.push([lineOf(start), lineOf(end)]);
    re.lastIndex = Math.max(re.lastIndex, end);
  }
  return ranges;
}

/** Where the item that starts at `from` ends: its closing brace, or its `;`. */
function itemEnd(text: string, from: number): number {
  let depth = 0;
  let k = from;
  while (k < text.length) {
    const c = text[k];
    const next = text[k + 1];
    if (c === "/" && next === "/") {
      k = text.indexOf("\n", k);
      if (k === -1) return text.length - 1;
      continue;
    }
    if (c === "/" && next === "*") {
      const e = text.indexOf("*/", k + 2);
      k = e === -1 ? text.length : e + 2;
      continue;
    }
    if (c === '"') {
      k = stringEnd(text, k);
      continue;
    }
    if (c === "r" && /^r#*"/.test(text.slice(k, k + 10)) && !/[A-Za-z0-9_]/.test(text[k - 1] ?? "")) {
      const hashes = text.slice(k + 1).match(/^#*/)![0];
      const close = `"${hashes}`;
      const e = text.indexOf(close, k + 2 + hashes.length);
      k = e === -1 ? text.length : e + close.length;
      continue;
    }
    if (c === "'") {
      // A character literal, not a lifetime: 'x', '\n', '\u{..}'.
      const lit = text.slice(k).match(/^'(?:\\(?:u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^\\'\n])'/u);
      if (lit) {
        k += lit[0].length;
        continue;
      }
    }
    if (c === "#" && next === "[" && depth === 0) {
      // Another attribute on the same item.
      const e = text.indexOf("]", k);
      k = e === -1 ? text.length : e + 1;
      continue;
    }
    if (c === "{") depth++;
    if (c === "}") {
      depth--;
      if (depth === 0) return k;
    }
    if (c === ";" && depth === 0) return k;
    k++;
  }
  return text.length - 1;
}

function stringEnd(text: string, k: number): number {
  k++;
  while (k < text.length) {
    if (text[k] === "\\") k += 2;
    else if (text[k] === '"') return k + 1;
    else k++;
  }
  return k;
}

/** The comment on a line of Rust: the text after `//`, if any. */
export function commentOf(line: string): string | undefined {
  // Skip `//` inside strings and URLs.
  let inString = false;
  for (let k = 0; k < line.length; k++) {
    const c = line[k];
    if (c === "\\" && inString) {
      k++;
      continue;
    }
    if (c === '"') inString = !inString;
    if (!inString && c === "/" && line[k + 1] === "/" && line[k - 1] !== ":") return line.slice(k + 2);
  }
  const block = line.match(/^\s*\*\s?(.*)$/);
  return block ? block[1] : undefined;
}

// A section number: 7.1, an appendix's D.4, or a whole section such as 13
// that has no subsections. Never part of a longer number, such as an RFC's
// 2.1.3.
const NUM = String.raw`(?:\d{1,2}(?:\.\d{1,2})?|[A-Z]\.\d{1,2})(?!\.?\d)`;
const SECTION = String.raw`${NUM}(?:\s*(?:[-–]|to)\s*${NUM})?`;

/**
 * The spec sections a comment cites: groups in parentheses made of
 * section numbers, such as "(7.1)", "(5.6, 12.11)" or "(SPEC 3.1-3.3)", and
 * "Section 2.2" or "SPEC 4.5" anywhere. Ranges are kept as written. Whole
 * numbers, such as "(11)" or "(4.5, 15)", are returned too; a group of
 * whole numbers alone counts only when nothing else is in its parentheses,
 * so "(2 bytes)" cites nothing. The caller keeps the numbers the spec has.
 */
export function sectionsInComment(comment: string): string[] {
  const found: string[] = [];
  const group = new RegExp(String.raw`\(\s*(SPEC\s+|spec\s+|[Ss]ections?\s+|§\s*)?(${SECTION}(?:\s*(?:,|and)\s*(?:${SECTION}))*)\b([^()]*)\)`, "g");
  for (const m of comment.matchAll(group)) {
    if (!m[1] && !m[2].includes(".") && m[3].trim()) continue;
    for (const s of m[2].matchAll(new RegExp(SECTION, "g"))) found.push(s[0].replace(/\s*(?:[-–]|to)\s*/, "-"));
  }
  const named = new RegExp(String.raw`(?:SPEC|[Ss]ection|§)\s*(${SECTION})`, "g");
  for (const m of comment.matchAll(named)) found.push(m[1].replace(/\s*(?:[-–]|to)\s*/, "-"));
  return [...new Set(found)];
}

/** Ranges such as 3.1-3.3, or B.1-B.3, become 3.1, 3.2, 3.3. */
export function expandSections(sections: string[]): string[] {
  const out = new Set<string>();
  for (const s of sections) {
    const m = s.match(/^(\d+|[A-Z])\.(\d+)-(\d+|[A-Z])\.(\d+)$/);
    if (m && m[1] === m[3] && Number(m[4]) >= Number(m[2]) && Number(m[4]) - Number(m[2]) < 30) {
      for (let k = Number(m[2]); k <= Number(m[4]); k++) out.add(`${m[1]}.${k}`);
    } else if (m) {
      out.add(`${m[1]}.${m[2]}`);
      out.add(`${m[3]}.${m[4]}`);
    } else {
      out.add(s);
    }
  }
  return [...out];
}

/** Every line with a comment that cites a section. */
export function citationsIn(lines: string[], offset = 0): { line: number; sections: string[] }[] {
  const out: { line: number; sections: string[] }[] = [];
  lines.forEach((text, k) => {
    const c = commentOf(text);
    if (!c) return;
    const sections = sectionsInComment(c);
    if (sections.length) out.push({ line: offset + k + 1, sections });
  });
  return out;
}

/** The `///` doc comment above line `start` (1-based), attributes skipped. */
export function docAbove(lines: string[], start: number): string {
  const doc: string[] = [];
  let k = start - 2;
  while (k >= 0) {
    const t = lines[k].trim();
    if (t.startsWith("///")) doc.unshift(t.replace(/^\/\/\/ ?/, ""));
    else if (t.startsWith("#[") || t === "") {
      if (t === "" && doc.length) break;
    } else break;
    k--;
  }
  return doc.join("\n").trim();
}

export interface TlcResult {
  result: "pass" | "violation" | "stopped" | "error";
  invariant?: string;
  states?: number;
  distinct?: number;
  depth?: number;
  traceLength?: number;
}

/** What a TLC run found, from its log and exit code. */
export function parseTlc(log: string, exit: number): TlcResult {
  const num = (s: string) => Number(s.replace(/,/g, ""));
  const out: TlcResult = { result: "error" };
  const finals = [...log.matchAll(/([\d,]+) states generated(?: \([^)]*\))?,\s*([\d,]+) distinct states found/g)];
  if (finals.length) {
    const f = finals[finals.length - 1];
    out.states = num(f[1]);
    out.distinct = num(f[2]);
  }
  const depth = log.match(/depth of the complete state graph search is ([\d,]+)/);
  if (depth) out.depth = num(depth[1]);
  const progress = [...log.matchAll(/Progress\((\d+)\)/g)];
  if (!depth && progress.length) out.depth = num(progress[progress.length - 1][1]);
  const inv = log.match(/(?:Invariant|Property|Temporal property) (\w+) is violated/);
  if (/No error has been found/.test(log)) out.result = "pass";
  else if (inv) {
    out.result = "violation";
    out.invariant = inv[1];
    const states = [...log.matchAll(/^State (\d+):/gm)];
    if (states.length) out.traceLength = Math.max(...states.map((s) => Number(s[1])));
  } else if (exit === 124) out.result = "stopped";
  return out;
}

export interface Section {
  num: string;
  title: string;
  depth: number;
}

/** The numbered sections and appendices of a spec, from its headings. */
export function specSections(text: string): Section[] {
  const out: Section[] = [];
  let inCode = false;
  for (const line of text.split("\n")) {
    if (/^\s{0,3}(```|~~~)/.test(line)) inCode = !inCode;
    if (inCode) continue;
    const m = line.match(/^(#{2,3}) (?:Appendix )?([A-Z]|\d+)((?:\.\d+)*)\.? (.+)$/);
    if (!m) continue;
    out.push({ num: m[2] + m[3], title: m[4].trim(), depth: m[1].length - 1 });
  }
  return out;
}

/**
 * Per section, how many `C:` and `S:` example lines its code blocks hold,
 * as the spec tests (crates/risala-proto/tests) find them. Appendix B's
 * AUTH command counts as a client example.
 */
export function specExamples(text: string): Map<string, { client: number; server: number }> {
  const out = new Map<string, { client: number; server: number }>();
  let section = "";
  let fence: string | undefined;
  for (const line of text.split("\n")) {
    const f = line.match(/^ {0,3}(`{3,}|~{3,})(.*)$/);
    if (f) {
      if (!fence) {
        fence = f[1];
        continue;
      }
      if (f[1][0] === fence[0] && f[1].length >= fence.length && !f[2].trim()) {
        fence = undefined;
        continue;
      }
    }
    if (!fence) {
      const h = line.match(/^#{2,3} (?:Appendix )?([A-Z]|\d+)((?:\.\d+)*)\.? /);
      if (h) section = h[1] + h[2];
      continue;
    }
    const t = line.trimStart();
    const e = out.get(section) ?? { client: 0, server: 0 };
    if (/^C: \S/.test(t) || (section.startsWith("B") && line.startsWith("AUTH "))) e.client++;
    else if (/^S: \S/.test(t)) e.server++;
    else continue;
    out.set(section, e);
  }
  return out;
}

/**
 * Per file, per line, the count, from `xcrun xccov view --archive --json`:
 * an object from each file's path to its lines, each with `line`,
 * `isExecutable` and `executionCount`.
 */
export function xccovLines(json: any, normalise: (p: string) => string | undefined): Map<string, LineCounts> {
  const out = new Map<string, LineCounts>();
  const entries: [string, any[]][] = Array.isArray(json?.files)
    ? json.files.map((f: any) => [f.path, f.lines])
    : Object.entries(json ?? {});
  for (const [file, lines] of entries) {
    const rel = normalise(file);
    if (!rel || !Array.isArray(lines)) continue;
    const counts: LineCounts = new Map();
    for (const l of lines) {
      if (!l?.isExecutable) continue;
      counts.set(Number(l.line), Number(l.executionCount ?? l.count ?? 0));
    }
    out.set(rel, counts);
  }
  return out;
}

/**
 * A path relative to the checkout, from a tool's path: relative already, or
 * absolute under `root`, or absolute under another checkout (a CI runner's),
 * found by its crates/ or clients/ part.
 */
export function normalisePath(p: string, root: string): string | undefined {
  if (!p) return undefined;
  const slashed = p.replace(/\\/g, "/");
  const r = root.replace(/\\/g, "/").replace(/\/$/, "");
  if (slashed.startsWith(`${r}/`)) return slashed.slice(r.length + 1);
  if (!slashed.startsWith("/")) return slashed.replace(/^\.\//, "");
  const m = slashed.match(/\/((?:crates|clients)\/.+)$/);
  return m ? m[1] : undefined;
}
