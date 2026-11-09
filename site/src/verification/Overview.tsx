// The verification overview: one number, the share of code lines some
// check reaches, then what makes it up. Each kind of check opens on its
// tests, targets, proofs or model runs. The source tree is in Tree.tsx.

import type { ReactNode } from "react";
import { DATA, LAYERS, REPO_URL, type Layer, count, date, duration, fileUrl, hasLayer, useJson } from "./data";
import { Frame } from "./Tree";
import type { Summary, TestStatus } from "./types";
import { Bar, Crumbs, Glyph, Hero, Loading, Pct } from "./ui";

export default function Overview() {
  const load = useJson<Summary>(`${DATA}/summary.json`);
  if (load.state === "loading") return <Loading />;
  const s = load.state === "ready" ? load.data : undefined;
  const measured = s && (s.has.unit || s.has.integration || s.has.fuzz || s.has.kani);
  const bad = s ? failures(s) : 0;
  return (
    <Frame summary={s} home>
      <section className="panel">
        <div className="panel-head v-head">
          <Crumbs parts={[{ label: "verification" }]} />
          <a href="/verification/spec/">spec →</a>
        </div>
        <Hero
          tally={measured ? s.totals.any : undefined}
          label="lines checked"
          title="code lines a unit test, integration test, fuzz input or kani proof reaches. test code is not counted."
        >
          {s && (
            <>
              {s.commit && <a href={`${REPO_URL}/commit/${s.commit}`}>{s.commit.slice(0, 10)}</a>}
              <span>{date(s.generated)}</span>
              {s.runUrl && <a href={s.runUrl}>ci</a>}
              {bad > 0 && <a className="miss" href="#checks">✗ {count(bad)} failing</a>}
            </>
          )}
        </Hero>
        {s && <Checks summary={s} />}
      </section>
    </Frame>
  );
}

const testsFailed = (ts: (TestStatus | null)[]) =>
  ts.reduce((a, t) => a + (t ? (t.failed ?? 0) || (t.exit !== 0 ? 1 : 0) : 0), 0);

/** Failed tests, proofs that did not succeed, and TLC runs that did not go as expected. */
function failures(s: Summary): number {
  return (
    testsFailed([s.tests.unit, s.tests.integration, s.tests.swift]) +
    s.kani.filter((p) => p.status !== "success").length +
    s.tla.runs.filter((r) => r.result !== "none" && !r.asExpected).length
  );
}

/** ✓ passed ✗ failed, with the failures only when there are some. */
function Score({ ok, bad, of }: { ok: number; bad: number; of?: number }) {
  return (
    <span className="v-score">
      <span className="ok">✓ {count(ok)}{of !== undefined && ` / ${count(of)}`}</span>
      {bad > 0 && <span className="miss">✗ {count(bad)}</span>}
    </span>
  );
}

function TestScore({ ts }: { ts: (TestStatus | null)[] }) {
  const ran = ts.filter((t) => t !== null);
  if (!ran.length) return <span className="dim">-</span>;
  return <Score ok={ran.reduce((a, t) => a + (t.passed ?? 0), 0)} bad={testsFailed(ran)} />;
}

const STATUS: Record<string, [string, string]> = {
  success: ["✓", "presence"],
  failure: ["✗", "wax"],
  timeout: ["⧗", "mention"],
};

function Checks({ summary: s }: { summary: Summary }) {
  const [unit, integration, fuzz, kani, tla] = LAYERS;
  const fuzzed = s.fuzz.reduce((a, t) => a + (t.seconds ?? 0), 0);
  const proved = s.kani.filter((p) => p.status === "success").length;
  const ran = s.tla.runs.filter((r) => r.result !== "none");
  const asExpected = ran.filter((r) => r.asExpected).length;
  // Failures first.
  const proofs = [...s.kani].sort((a, b) => Number(a.status === "success") - Number(b.status === "success"));
  return (
    <ul className="v-checks" id="checks">
      <Check layer={unit} s={s} score={<TestScore ts={[s.tests.unit, s.tests.swift]} />} />
      <Check layer={integration} s={s} score={<TestScore ts={[s.tests.integration]} />} />
      <Check layer={fuzz} s={s} score={<span>{s.fuzz.length} targets · {duration(fuzzed)}</span>}>
        <ul className="v-items">
          {s.fuzz.map((t) => (
            <li key={`${t.crate}/${t.target}`} className={t.hasCoverage ? "" : "dim"} title={t.hasCoverage ? undefined : "no coverage"}>
              <span className="id">
                {t.crate}/<strong>{t.target}</strong>
              </span>
              <span className="label">{count(t.inputs)} inputs</span>
              <span className="label">{duration(t.seconds)}</span>
            </li>
          ))}
        </ul>
      </Check>
      <Check layer={kani} s={s} score={<Score ok={proved} bad={s.kani.length - proved} of={s.kani.length} />}>
        <ul className="v-items">
          {proofs.map((p) => {
            const [glyph, tint] = STATUS[p.status] ?? ["?", "mention"];
            return (
              <li key={p.id} title={p.doc}>
                <Glyph symbol={glyph} tint={tint} />
                <a className="id" href={fileUrl(p.path, p.line)}>
                  {p.id}
                </a>
                {p.coverage !== "line" && (
                  <span className="label" title={p.coverage === "function" ? "function-level coverage, approximate" : "no coverage"}>
                    {p.coverage === "function" ? "≈" : "-"}
                  </span>
                )}
                {p.sections.length > 0 && <span className="label">§{p.sections.join(" §")}</span>}
                <span className="label">{p.durationMs !== undefined ? duration(p.durationMs / 1000) : "-"}</span>
              </li>
            );
          })}
        </ul>
      </Check>
      <Check layer={tla} s={s} score={ran.length ? <Score ok={asExpected} bad={ran.length - asExpected} of={s.tla.runs.length} /> : undefined}>
        <ul className="v-items">
          {s.tla.models.map((m) =>
            s.tla.runs
              .filter((r) => r.model === m.id)
              .map((r) => {
                const none = r.result === "none";
                return (
                  <li key={`${m.id}/${r.config}`} title={r.meaning}>
                    <Glyph symbol={none ? "-" : r.asExpected ? "✓" : "✗"} tint={none ? "ink" : r.asExpected ? "presence" : "wax"} />
                    <a className="id" href={`${REPO_URL}/blob/${s.commit ?? "main"}/${m.file.replace(/[^/]+$/, r.config)}`} title={m.summary}>
                      {m.title}/<strong>{r.config}</strong>
                    </a>
                    {!none && (
                      <span className={`label${r.asExpected ? "" : " miss"}`}>
                        {r.result}
                        {r.asExpected && r.expect !== "pass" ? " (expected)" : ""}
                      </span>
                    )}
                    {r.distinct !== undefined && <span className="label">{count(r.distinct)} states</span>}
                    {r.seconds !== undefined && <span className="label">{duration(r.seconds)}</span>}
                  </li>
                );
              }),
          )}
        </ul>
      </Check>
    </ul>
  );
}

/** One kind of check: its share of lines, its score, and what it ran. */
function Check({ layer, s, score, children }: { layer: Layer; s: Summary; score?: ReactNode; children?: ReactNode }) {
  const has = hasLayer(s, layer.key);
  // The TLA+ model checks the spec, not the code: no share of lines.
  const lines = layer.key !== "tla";
  const row = (
    <>
      <span className="name" title={layer.tip}>
        <span className="sw" aria-hidden="true" />
        {layer.label}
      </span>
      {lines || !has ? <Bar tally={has ? s.totals[layer.key] : undefined} color={layer.color} /> : <span />}
      {lines ? <Pct tally={has ? s.totals[layer.key] : undefined} /> : <span />}
      <span className="score">{has && score}</span>
    </>
  );
  return (
    <li style={{ ["--c" as string]: layer.color }}>
      {children && has ? (
        <details>
          <summary className="row">{row}</summary>
          {children}
        </details>
      ) : (
        <div className="row">{row}</div>
      )}
    </li>
  );
}
