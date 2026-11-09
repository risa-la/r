// The source tree, crate by crate, beside every verification page on wide
// screens. On narrow ones it sits under the overview and nowhere else.

import { useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { fileUrl, shortPath } from "./data";
import type { FileSummary, Summary } from "./types";
import { Bar, Pct } from "./ui";

const KEY = "verification-filter";
const any = "var(--text-secondary)";

/** A page with the tree on its left; `home` keeps the tree inline on phones. */
export function Frame({ summary, current, home, children }: { summary?: Summary; current?: string; home?: boolean; children: ReactNode }) {
  return (
    <div className={`v-frame${summary ? " tree" : ""}${home ? " home" : ""}`}>
      {summary && <Tree summary={summary} current={current} />}
      <div className="v-main">{children}</div>
    </div>
  );
}

function Tree({ summary, current }: { summary: Summary; current?: string }) {
  // The filter follows the reader from page to page.
  const [query, setQuery] = useState(() => {
    try {
      return sessionStorage.getItem(KEY) ?? "";
    } catch {
      return "";
    }
  });
  const filter = (q: string) => {
    setQuery(q);
    try {
      sessionStorage.setItem(KEY, q);
    } catch {
      // Blocked storage: the filter just doesn't follow.
    }
  };
  const groups = useMemo(() => {
    const q = query.trim().toLowerCase();
    const map = new Map<string, FileSummary[]>();
    for (const f of summary.files) {
      if (q && !f.path.toLowerCase().includes(q)) continue;
      map.set(f.crate, [...(map.get(f.crate) ?? []), f]);
    }
    return [...map.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [summary, query]);
  const crateTally = new Map(summary.crates.map((c) => [c.name, c.tally.any]));
  const crateOf = summary.files.find((f) => f.path === current)?.crate;

  // The current file in the middle of the tree's own scroll.
  const list = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = list.current?.querySelector<HTMLElement>("[aria-current]");
    if (el && list.current) list.current.scrollTop = el.offsetTop - list.current.clientHeight / 2;
  }, []);

  return (
    <nav className="panel v-tree" aria-label="source">
      <div className="panel-head">
        <input type="search" spellCheck={false} value={query} onChange={(e) => filter(e.target.value)} placeholder="filter" aria-label="filter files" />
      </div>
      <div className="list" ref={list}>
        {groups.map(([crate, files]) => (
          <details key={crate} open={!!query.trim() || crate === crateOf}>
            <summary className="row">
              <span className="crate" title={crate}>
                {crate}
              </span>
              <Bar tally={crateTally.get(crate)} color={any} />
              <Pct tally={crateTally.get(crate)} />
            </summary>
            <ul>
              {files.map((f) => (
                <li key={f.path}>
                  <a className={`row${f.test ? " test" : ""}`} href={fileUrl(f.path)} title={f.path} aria-current={f.path === current ? "page" : undefined}>
                    <span className="path">{shortPath(f)}</span>
                    {f.test ? (
                      <span className="label">test</span>
                    ) : (
                      <>
                        <Bar tally={f.tally.any} color={any} />
                        <Pct tally={f.tally.any} />
                      </>
                    )}
                  </a>
                </li>
              ))}
            </ul>
          </details>
        ))}
      </div>
    </nav>
  );
}
