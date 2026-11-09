// What the verification pages share: the layers of evidence, fetching the
// data, and number formatting.

import { useEffect, useState } from "react";
import { REPO_URL } from "../docs";
import type { FileSummary, LayerKey, Summary, Tally } from "./types";

export { REPO_URL };
export const DATA = "/verification-data";

export interface Layer {
  key: LayerKey;
  short: "u" | "i" | "f" | "k" | "t";
  label: string;
  color: string;
  // What the layer can and cannot show, for a tooltip.
  tip: string;
}

// Stripe order beside the line number, left to right.
export const LAYERS: Layer[] = [
  { key: "unit", short: "u", label: "unit", color: "var(--presence)", tip: "lines each crate's own tests run. a line that ran was not necessarily checked." },
  { key: "integration", short: "i", label: "integration", color: "var(--mode)", tip: "lines the tests in tests/ run, spec examples included. a line that ran was not necessarily checked." },
  { key: "fuzz", short: "f", label: "fuzzing", color: "var(--mention)", tip: "lines the saved fuzz corpus reaches. more hours fuzzed grow it." },
  { key: "kani", short: "k", label: "kani", color: "var(--location)", tip: "lines a kani proof reaches. a proof holds for every input within its bounds, for the property it states." },
  { key: "tla", short: "t", label: "tla+", color: "var(--ink)", tip: "a model of the spec, not of this code, checked within small bounds. marks functions that cite a section it covers." },
];

/** Whether results exist for a layer, for code in the given language. */
export function hasLayer(summary: Summary | undefined, key: LayerKey, lang: "rust" | "swift" = "rust"): boolean {
  if (!summary) return false;
  if (lang === "swift") return key === "unit" && summary.has.swift;
  return summary.has[key];
}

export type Load<T> = { state: "loading" } | { state: "missing" } | { state: "ready"; data: T };

/** Fetches a JSON file once; a 404 or bad JSON is "missing". */
export function useJson<T>(url: string): Load<T> {
  const [load, setLoad] = useState<Load<T>>({ state: "loading" });
  useEffect(() => {
    let live = true;
    fetch(url)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then((data: T) => live && setLoad({ state: "ready", data }))
      .catch(() => live && setLoad({ state: "missing" }));
    return () => {
      live = false;
    };
  }, [url]);
  return load;
}

export const fileUrl = (p: string, line?: number) => `/verification/src/${p}/${line ? `#L${line}` : ""}`;

export const githubUrl = (commit: string | null, p: string, line?: number) =>
  `${REPO_URL}/blob/${commit ?? "main"}/${p}${line ? `#L${line}` : ""}`;

export function ratio(t: Tally | undefined): number | undefined {
  return t && t.total ? t.covered / t.total : undefined;
}

export function pct(t: Tally | undefined): string {
  const r = ratio(t);
  if (r === undefined) return "-";
  // 99.96% should not read as 100%.
  const v = Math.floor(r * 1000) / 10;
  return `${v.toFixed(1)}%`;
}

export function count(n: number | undefined): string {
  return n === undefined ? "-" : n.toLocaleString("en");
}

export function duration(seconds: number | undefined): string {
  if (seconds === undefined) return "-";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  const h = seconds / 3600;
  return `${h < 10 ? h.toFixed(1) : Math.round(h)}h`;
}

export function date(iso: string | null | undefined): string {
  if (!iso) return "-";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().replace("T", " ").slice(0, 16) + " utc";
}

/** Directory and name of a file within its crate, for lists. */
export function shortPath(f: Pick<FileSummary, "path" | "crate" | "lang">): string {
  return f.lang === "swift" ? f.path.replace(/^clients\/apple\//, "") : f.path.replace(/^crates\/[^/]+\//, "");
}

/** Layer toggles, remembered per viewer when the browser allows. */
export function readToggles(): Record<LayerKey, boolean> {
  const all = { unit: true, integration: true, fuzz: true, kani: true, tla: true };
  try {
    return { ...all, ...JSON.parse(localStorage.getItem("verification-layers") ?? "{}") };
  } catch {
    return all;
  }
}

export function saveToggles(t: Record<LayerKey, boolean>) {
  try {
    localStorage.setItem("verification-layers", JSON.stringify(t));
  } catch {
    // Private windows and blocked storage: the toggles just don't persist.
  }
}
