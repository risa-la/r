// The shapes of the JSON that verification/assemble.ts writes to
// public/verification-data/. Kept in step with that script by hand.

export type LayerKey = "unit" | "integration" | "fuzz" | "kani" | "tla";

export interface Tally {
  covered: number;
  total: number;
}

export type Tallies = Record<LayerKey | "any", Tally>;

export interface TestStatus {
  exit: number;
  passed?: number;
  failed?: number;
  ignored?: number;
}

export interface FuzzTarget {
  crate: string;
  target: string;
  inputs?: number;
  seconds?: number;
  runs?: number;
  last?: string;
  hasCoverage: boolean;
}

export interface Proof {
  id: string;
  crate: string;
  path: string;
  line: number;
  endLine: number;
  status: string; // success, failure, timeout or unknown
  durationMs?: number;
  doc: string;
  sections: string[];
  coverage: "line" | "function" | "none";
}

export interface TlaRun {
  model: string;
  config: string;
  expect: string;
  meaning: string;
  result: string; // pass, violation, stopped, error or none
  asExpected: boolean;
  invariant?: string;
  states?: number;
  distinct?: number;
  depth?: number;
  traceLength?: number;
  seconds?: number;
  limit?: number;
}

export interface TlaModel {
  id: string;
  title: string;
  file: string;
  readme: string;
  draft: string;
  summary: string;
  sections: string[];
}

export interface FileSummary {
  path: string;
  lang: "rust" | "swift";
  crate: string;
  test: boolean;
  lines: number;
  tally: Tallies;
}

export interface Summary {
  commit: string | null;
  runUrl: string | null;
  generated: string | null;
  assembled: string;
  has: Record<"unit" | "integration" | "fuzz" | "kani" | "tla" | "swift", boolean>;
  tests: Record<"unit" | "integration" | "swift", TestStatus | null>;
  fuzz: FuzzTarget[];
  kani: Proof[];
  tla: { runs: TlaRun[]; models: TlaModel[] };
  totals: Tallies;
  crates: { name: string; tally: Tallies }[];
  files: FileSummary[];
}

/** What reaches one line. Absent fields: that tool does not see the line. */
export interface LineEntry {
  u?: number; // unit test hits
  i?: number; // integration test hits
  f?: number[]; // fuzz targets that reach it; empty: instrumented, not reached
  k?: number[]; // Kani proofs that reach it
  km?: number[]; // Kani proofs that covered its region but missed it
  t?: string[]; // spec sections a TLA+ model covers
}

export interface FileData {
  path: string;
  lang: "rust" | "swift";
  crate: string;
  test: boolean;
  testRanges: [number, number][];
  source: string;
  lines: Record<string, LineEntry>;
}

export interface SpecSection {
  num: string;
  title: string;
  depth: number;
  examples: { client: number; server: number };
  code: [string, number][];
  tests: [string, number][];
  tla: string[];
  kani: number[];
}

export interface SpecData {
  codeDraft: string;
  codeNote: string;
  drafts: { id: string; published: boolean; sections: SpecSection[] }[];
}
