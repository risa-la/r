// Small pieces the verification pages share. Crumbs and Glyph mirror the
// site's Astro components (Breadcrumb, Glyph), which React cannot use.

import type { ReactNode } from "react";
import { pct, ratio } from "./data";
import type { Tally } from "./types";

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

export function Glyph({ symbol, tint = "ink" }: { symbol: string; tint?: string }) {
  return (
    <span className="v-glyph" style={{ ["--tint" as string]: `var(--${tint})` }} aria-hidden="true">
      {symbol}
    </span>
  );
}

/** A thin bar for a share of lines, or "no data" when there is nothing to count. */
export function Bar({ tally, color }: { tally: Tally | undefined; color: string }) {
  const r = ratio(tally);
  if (r === undefined) return <span className="v-bar none label">no data</span>;
  return (
    <span className="v-bar" title={`${tally!.covered.toLocaleString("en")} / ${tally!.total.toLocaleString("en")}`}>
      <span className="track">
        <span className="fill" style={{ width: `${r * 100}%`, background: color }} />
      </span>
    </span>
  );
}

/** A share of lines; blank without data, where the bar says so. */
export function Pct({ tally }: { tally: Tally | undefined }) {
  return <span className="v-pct">{ratio(tally) === undefined ? "" : pct(tally)}</span>;
}

/** A page's one number, its bar, and a line of small print under it. */
export function Hero({ tally, label, title, children }: { tally: Tally | undefined; label: string; title: string; children?: ReactNode }) {
  const none = ratio(tally) === undefined;
  return (
    <div className="v-hero">
      <div className="v-hero-num" title={title}>
        <span className={`v-big${none ? " none" : ""}`}>{none ? "no data" : pct(tally)}</span>
        {!none && <span className="label">{label}</span>}
      </div>
      {!none && <Bar tally={tally} color="var(--ink)" />}
      {children && <div className="v-hero-foot label">{children}</div>}
    </div>
  );
}

export function NoResults() {
  return <span className="miss">no results yet</span>;
}

export function Loading() {
  return <p className="v-loading label">loading…</p>;
}
