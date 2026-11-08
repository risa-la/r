// Small pieces the verification pages share. They mirror the site's Astro
// components (Breadcrumb, Glyph), which React cannot use.

import type { ReactNode } from "react";
import { LAYERS, hasLayer, pct, ratio } from "./data";
import type { Summary, Tally } from "./types";

export function Crumbs({ parts }: { parts: { label: string; href?: string }[] }) {
  return (
    <div className="v-crumbs" role="heading" aria-level={2}>
      <a className="root" href="/">
        risala
      </a>
      {parts.map(({ label, href }, k) => (
        <span key={k} className="part-wrap">
          <span className="sep" aria-hidden="true">
            /
          </span>
          {href ? (
            <a className="part" href={href}>
              {label}
            </a>
          ) : (
            <span className="part">{label}</span>
          )}
        </span>
      ))}
    </div>
  );
}

export function Panel({ crumbs, children, className, id }: { crumbs: string; children: ReactNode; className?: string; id?: string }) {
  return (
    <section className={`panel ${className ?? ""}`} id={id}>
      <div className="panel-head">
        <Crumbs parts={[{ label: "verification", href: "/verification/" }, { label: crumbs }]} />
      </div>
      {children}
    </section>
  );
}

export function Glyph({ symbol, tint = "ink" }: { symbol: string; tint?: string }) {
  return (
    <span className="v-glyph" style={{ ["--tint" as string]: `var(--${tint})` }} aria-hidden="true">
      {symbol}
    </span>
  );
}

/** A thin bar for a share of lines. Empty, with a dash, when there is nothing to count. */
export function Bar({ tally, color, title }: { tally: Tally | undefined; color: string; title?: string }) {
  const r = ratio(tally);
  return (
    <span className="v-bar" title={title ?? (tally ? `${tally.covered} of ${tally.total} lines` : undefined)}>
      <span className="track">{r !== undefined && <span className="fill" style={{ width: `${r * 100}%`, background: color }} />}</span>
    </span>
  );
}

export function Pct({ tally }: { tally: Tally | undefined }) {
  return <span className="v-pct">{pct(tally)}</span>;
}

/**
 * The "no results" line: for the whole commit, or for the layers that are
 * missing. Nothing when every layer has results.
 */
export function NoResults({ summary, lang }: { summary: Summary | undefined; lang?: "rust" | "swift" }) {
  if (!summary) {
    return (
      <p className="v-banner">
        <strong>no results for this commit yet.</strong> the verification run has not produced any data for this build of
        the site.
      </p>
    );
  }
  const layers = lang === "swift" ? LAYERS.filter((l) => l.key === "unit") : LAYERS;
  const missing = layers.filter((l) => !hasLayer(summary, l.key, lang));
  if (!missing.length) return null;
  const none = missing.length === layers.length && (lang === "swift" || !summary.has.swift);
  return (
    <p className="v-banner">
      <strong>{none ? "no results for this commit yet." : "no results for this commit yet:"}</strong>{" "}
      {none ? (
        "the columns below are empty until the verification run finishes."
      ) : (
        <>
          {missing.map((l) => (lang === "swift" ? "swift unit tests" : l.label)).join(", ")}. those columns are empty;
          the rest are current.
        </>
      )}
    </p>
  );
}

export function Loading() {
  return <p className="v-loading label">loading…</p>;
}
