// The verification overview: what the results are for, the totals per
// layer and per crate, how the test runs went, every Kani proof, fuzz
// target and TLC run, what each method can and cannot show, and every
// source file.

import { useMemo, useState } from "react";
import { DATA, LAYERS, REPO_URL, count, date, duration, fileUrl, hasLayer, pct, shortPath, useJson } from "./data";
import type { FileSummary, Proof, Summary, TestStatus, TlaRun } from "./types";
import { Bar, Crumbs, Glyph, Loading, NoResults, Panel, Pct } from "./ui";

export default function Overview() {
  const summary = useJson<Summary>(`${DATA}/summary.json`);
  if (summary.state === "loading") return <Loading />;
  const s = summary.state === "ready" ? summary.data : undefined;
  return (
    <>
      <Head summary={s} />
      {s && <Totals summary={s} />}
      <Limits />
      {s && <Tests summary={s} />}
      {s && <Crates summary={s} />}
      {s && <Proofs summary={s} />}
      {s && <Fuzz summary={s} />}
      {s && <Tla summary={s} />}
      {s && <Files summary={s} />}
    </>
  );
}

function Head({ summary }: { summary: Summary | undefined }) {
  const commit = summary?.commit;
  return (
    <section className="panel">
      <div className="panel-head">
        <Crumbs parts={[{ label: "verification" }]} />
      </div>
      <div className="panel-body">
        <h1 className="v-title">how the code is checked</h1>
        <p className="v-lede">
          every line of the rust crates and the apple client, with what reaches it: unit tests, integration tests, fuzzing
          and kani proofs, and the spec sections a tla+ model covers. the numbers are from one run over one commit, and
          they are shown as they came out, failures included.
        </p>
        <div className="v-links">
          <a className="button" href="/verification/spec/">
            by spec section
          </a>
          <a className="button" href="#files">
            browse the source
          </a>
        </div>
        {summary && (
          <dl className="v-meta">
            <div>
              <dt className="label">commit</dt>
              <dd>{commit ? <a href={`${REPO_URL}/commit/${commit}`}>{commit.slice(0, 10)}</a> : "-"}</dd>
            </div>
            <div>
              <dt className="label">results from</dt>
              <dd>{date(summary.generated)}</dd>
            </div>
            <div>
              <dt className="label">run</dt>
              <dd>{summary.runUrl ? <a href={summary.runUrl}>ci log</a> : "-"}</dd>
            </div>
            <div>
              <dt className="label">assembled</dt>
              <dd>{date(summary.assembled)}</dd>
            </div>
          </dl>
        )}
        <NoResults summary={summary} />
        {summary && !summary.has.swift && hasAny(summary) && (
          <p className="v-banner">
            <strong>no results for this commit yet:</strong> swift unit tests for the apple client.
          </p>
        )}
      </div>
    </section>
  );
}

const hasAny = (s: Summary) => LAYERS.some((l) => s.has[l.key]);

function Totals({ summary }: { summary: Summary }) {
  const t = summary.totals;
  return (
    <Panel crumbs="totals">
      <div className="panel-body">
        <p className="v-note">
          share of the lines that code coverage counts as code, outside test code ({count(t.any.total)} lines).
        </p>
        <ul className="v-totals">
          <li className="any">
            <span className="name">any of the four</span>
            <Bar tally={t.any} color="var(--text-secondary)" />
            <Pct tally={t.any} />
            <span className="frac label">
              {count(t.any.covered)} / {count(t.any.total)}
            </span>
          </li>
          {LAYERS.map((l) => (
            <li key={l.key} style={{ ["--c" as string]: l.color }}>
              <span className="name">
                <span className="sw" aria-hidden="true" />
                {l.label}
              </span>
              <Bar tally={t[l.key]} color={l.color} />
              {hasLayer(summary, l.key) ? <Pct tally={t[l.key]} /> : <span className="v-pct dim">no results</span>}
              <span className="frac label">
                {count(t[l.key].covered)} / {count(t[l.key].total)}
              </span>
            </li>
          ))}
        </ul>
        <p className="v-note">
          tla+ counts lines in functions whose comments cite a section the model covers. the model checks the spec, not
          this code, so it is not in "any".
        </p>
      </div>
    </Panel>
  );
}

function Limits() {
  return (
    <Panel crumbs="what each method shows">
      <ul className="v-limits">
        <li>
          <Glyph symbol="✓" tint="presence" />
          <div>
            <strong>coverage is not correctness</strong>
            <span>
              a line that a test reaches ran at least once; it was not necessarily checked. the unit and integration
              columns say which code the tests exercise, not that it is right.
            </span>
          </div>
        </li>
        <li>
          <Glyph symbol="~" tint="mention" />
          <div>
            <strong>fuzzing finds what it has time to find</strong>
            <span>
              the fuzz column is what the saved inputs reach. more hours fuzzed grow it; a line no input reaches has
              not been fuzzed at all.
            </span>
          </div>
        </li>
        <li>
          <Glyph symbol="K" tint="location" />
          <div>
            <strong>kani is bounded, and proves only what a proof states</strong>
            <span>
              each proof checks every input up to its bounds, for the property written in it. a line a proof reaches is
              not proved correct in general, only for that property. where kani gives no line coverage, the page marks
              the functions a proof calls: that is an approximation.
            </span>
          </div>
        </li>
        <li>
          <Glyph symbol="◇" tint="ink" />
          <div>
            <strong>tla+ checks a model of the spec, not the code</strong>
            <span>
              the model was written against draft-02 and is checked within small bounds (a few devices, a few
              messages). a line in the tla+ column only cites a section the model covers.
            </span>
          </div>
        </li>
        <li>
          <Glyph symbol="}" tint="mode" />
          <div>
            <strong>only code lines are counted</strong>
            <span>
              in the source listing, braces, comments and blank lines inside a function are drawn like the code around
              them, so a function reads as one block. they are not counted in any percentage.
            </span>
          </div>
        </li>
      </ul>
    </Panel>
  );
}

function testFailed(t: TestStatus | null): boolean {
  return !!t && (t.exit !== 0 || (t.failed ?? 0) > 0);
}

function Tests({ summary }: { summary: Summary }) {
  const rows: [string, TestStatus | null][] = [
    ["unit tests", summary.tests.unit],
    ["integration tests", summary.tests.integration],
    ["swift unit tests", summary.tests.swift],
  ];
  return (
    <Panel crumbs="test runs">
      <ul className="v-rows-list">
        {rows.map(([name, t]) => (
          <li key={name} className={testFailed(t) ? "bad" : ""}>
            <Glyph symbol={!t ? "-" : testFailed(t) ? "✗" : "✓"} tint={!t ? "ink" : testFailed(t) ? "wax" : "presence"} />
            <span className="name">{name}</span>
            {!t ? (
              <span className="dim">no results</span>
            ) : (
              <span className="v-counts">
                {t.passed !== undefined && <span>{count(t.passed)} passed</span>}
                {t.failed !== undefined && <span className={t.failed ? "miss" : ""}>{count(t.failed)} failed</span>}
                {t.ignored !== undefined && <span>{count(t.ignored)} ignored</span>}
                <span className={t.exit ? "miss" : "dim"}>exit {t.exit}</span>
              </span>
            )}
          </li>
        ))}
      </ul>
      {rows.some(([, t]) => testFailed(t)) && (
        <p className="v-banner bad">
          <strong>some tests failed in this run.</strong> coverage from a failing run still shows what ran, but a failing
          test did not pass its checks.
        </p>
      )}
    </Panel>
  );
}

function Crates({ summary }: { summary: Summary }) {
  const layers = LAYERS.filter((l) => l.key !== "tla");
  return (
    <Panel crumbs="by crate">
      <div className="v-table-wrap">
        <table className="v-table">
          <thead>
            <tr className="label">
              <th>crate</th>
              <th>lines</th>
              {layers.map((l) => (
                <th key={l.key} style={{ ["--c" as string]: l.color }}>
                  <span className="sw" aria-hidden="true" />
                  {l.label.replace(" tests", "").replace(" proofs", "")}
                </th>
              ))}
              <th>any</th>
            </tr>
          </thead>
          <tbody>
            {summary.crates.map((c) => (
              <tr key={c.name}>
                <th scope="row">{c.name}</th>
                <td className="num">{count(c.tally.any.total)}</td>
                {layers.map((l) => (
                  <td key={l.key}>
                    <span className="cell">
                      <Bar tally={c.tally[l.key]} color={l.color} />
                      <Pct tally={c.tally[l.key]} />
                    </span>
                  </td>
                ))}
                <td>
                  <span className="cell">
                    <Bar tally={c.tally.any} color="var(--text-secondary)" />
                    <Pct tally={c.tally.any} />
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

const STATUS: Record<string, [string, string]> = {
  success: ["✓", "presence"],
  failure: ["✗", "wax"],
  timeout: ["⧗", "mention"],
};

function Proofs({ summary }: { summary: Summary }) {
  // Failures and timeouts first.
  const proofs = summary.kani
    .map((p, k) => [p, k] as const)
    .sort(([a], [b]) => Number(a.status === "success") - Number(b.status === "success"));
  const passed = summary.kani.filter((p) => p.status === "success").length;
  return (
    <Panel crumbs="kani proofs" id="kani">
      {!summary.has.kani ? (
        <p className="v-banner">
          <strong>no results for this commit yet:</strong> kani proofs.
        </p>
      ) : (
        <>
          <p className="v-note pad">
            {passed} of {summary.kani.length} proofs passed.
          </p>
          <ul className="v-proofs">
            {proofs.map(([p, k]) => (
              <ProofRow key={k} p={p} />
            ))}
          </ul>
        </>
      )}
    </Panel>
  );
}

function ProofRow({ p }: { p: Proof }) {
  const [glyph, tint] = STATUS[p.status] ?? ["?", "mention"];
  return (
    <li className={p.status === "success" ? "" : "bad"}>
      <Glyph symbol={glyph} tint={tint} />
      <div>
        <div className="top">
          <a href={fileUrl(p.path, p.line)} className="id">
            {p.id}
          </a>
          <span className="label">{p.crate}</span>
          <span className="label">{p.status}</span>
          <span className="label">{p.durationMs !== undefined ? duration(p.durationMs / 1000) : "-"}</span>
          <span className="label">
            {p.coverage === "line"
              ? "line coverage"
              : p.coverage === "function"
                ? "function-level coverage (an approximation)"
                : "no coverage"}
          </span>
          {p.sections.length > 0 && <span className="label">§ {p.sections.join(", ")}</span>}
        </div>
        {p.doc && <p className="doc">{p.doc}</p>}
      </div>
    </li>
  );
}

function Fuzz({ summary }: { summary: Summary }) {
  const total = summary.fuzz.reduce((a, t) => a + (t.seconds ?? 0), 0);
  return (
    <Panel crumbs="fuzz targets" id="fuzz">
      {!summary.has.fuzz && (
        <p className="v-banner">
          <strong>no results for this commit yet:</strong> fuzz coverage.
        </p>
      )}
      <p className="v-note pad">
        {summary.fuzz.length} targets, fuzzed for {duration(total)} in all.
      </p>
      <div className="v-table-wrap">
        <table className="v-table">
          <thead>
            <tr className="label">
              <th>target</th>
              <th>inputs</th>
              <th>fuzzed</th>
              <th>runs</th>
              <th>last</th>
              <th>coverage</th>
            </tr>
          </thead>
          <tbody>
            {summary.fuzz.map((t) => (
              <tr key={`${t.crate}/${t.target}`}>
                <th scope="row">
                  {t.crate}/<strong>{t.target}</strong>
                </th>
                <td className="num">{count(t.inputs)}</td>
                <td className="num">{duration(t.seconds)}</td>
                <td className="num">{count(t.runs)}</td>
                <td>{t.last ? date(t.last) : "-"}</td>
                <td>{t.hasCoverage ? "yes" : <span className="dim">none</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function Tla({ summary }: { summary: Summary }) {
  return (
    <Panel crumbs="tla+ model" id="tla">
      {!summary.has.tla && (
        <p className="v-banner">
          <strong>no results for this commit yet:</strong> tlc runs.
        </p>
      )}
      <ul className="v-tla">
        {summary.tla.models.map((m) => (
          <li key={m.id}>
            <div className="top">
              <a href={`${REPO_URL}/blob/${summary.commit ?? "main"}/${m.file}`} className="id">
                {m.title}
              </a>
              <span className="label">{m.draft}</span>
              <span className="label">§ {m.sections.join(", ")}</span>
            </div>
            <p className="doc">
              {m.summary} it models the spec, not the code. see{" "}
              <a href={`${REPO_URL}/blob/${summary.commit ?? "main"}/${m.readme}`}>{m.readme}</a>.
            </p>
            <ul className="runs">
              {summary.tla.runs
                .filter((r) => r.model === m.id)
                .map((r) => (
                  <TlaRunRow key={r.config} r={r} />
                ))}
            </ul>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function TlaRunRow({ r }: { r: TlaRun }) {
  const none = r.result === "none";
  const glyph = none ? "-" : r.asExpected ? "✓" : "✗";
  const tint = none ? "ink" : r.asExpected ? "presence" : "wax";
  return (
    <li className={!none && !r.asExpected ? "bad" : ""}>
      <Glyph symbol={glyph} tint={tint} />
      <div>
        <div className="top">
          <strong>{r.config}</strong>
          <span className="label">expected {r.expect}</span>
          <span className={`label${!none && !r.asExpected ? " miss" : ""}`}>{none ? "no results" : `got ${r.result}`}</span>
          {!none && <span className="label">{r.asExpected ? "as expected" : "not as expected"}</span>}
        </div>
        {!none && (
          <div className="v-counts label">
            <span>{count(r.states)} states</span>
            <span>{count(r.distinct)} distinct</span>
            <span>depth {count(r.depth)}</span>
            {r.invariant && (
              <span>
                violates <strong>{r.invariant}</strong>
                {r.traceLength !== undefined && ` in ${r.traceLength} steps`}
              </span>
            )}
            {r.seconds !== undefined && (
              <span>
                {duration(r.seconds)}
                {r.limit ? ` of ${duration(r.limit)}` : ""}
              </span>
            )}
          </div>
        )}
        <p className="doc">{r.meaning}</p>
      </div>
    </li>
  );
}

function Files({ summary }: { summary: Summary }) {
  const [query, setQuery] = useState("");
  const groups = useMemo(() => {
    const q = query.trim().toLowerCase();
    const map = new Map<string, FileSummary[]>();
    for (const f of summary.files) {
      if (q && !f.path.toLowerCase().includes(q)) continue;
      const list = map.get(f.crate) ?? [];
      list.push(f);
      map.set(f.crate, list);
    }
    return [...map.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [summary, query]);
  const crateTally = new Map(summary.crates.map((c) => [c.name, c.tally]));
  const layers = LAYERS.filter((l) => l.key !== "tla");
  return (
    <Panel crumbs="files" id="files" className="v-files">
      <div className="panel-body">
        <label className="v-filter">
          <span className="label">filter</span>
          <input type="search" spellCheck={false} value={query} onChange={(e) => setQuery(e.target.value)} placeholder="path contains" />
        </label>
        <div className="v-files-key label" aria-hidden="true">
          {layers.map((l) => (
            <span key={l.key} style={{ ["--c" as string]: l.color }}>
              <span className="sw" />
              {l.label}
            </span>
          ))}
        </div>
      </div>
      {groups.map(([crate, files]) => (
        <details key={crate} open={!!query.trim()}>
          <summary>
            <span className="crate">{crate}</span>
            <span className="label">{files.length} files</span>
            <span className="cell">
              <Bar tally={crateTally.get(crate)?.any} color="var(--text-secondary)" />
              <Pct tally={crateTally.get(crate)?.any} />
            </span>
          </summary>
          <ul>
            {files.map((f) => (
              <li key={f.path} className={f.test ? "test" : ""}>
                <a href={fileUrl(f.path)}>
                  <span className="path">{shortPath(f)}</span>
                  <span className="label n">{count(f.lines)}</span>
                  {f.test ? (
                    <span className="label tests">test code</span>
                  ) : (
                    <span className="minis" title={layers.map((l) => `${l.label} ${pct(f.tally[l.key])}`).join(", ")}>
                      {layers.map((l) => (
                        <Bar key={l.key} tally={f.tally[l.key]} color={l.color} title={`${l.label} ${pct(f.tally[l.key])}`} />
                      ))}
                      <Pct tally={f.tally.any} />
                    </span>
                  )}
                </a>
              </li>
            ))}
          </ul>
        </details>
      ))}
      {!groups.length && <p className="v-note pad">no file matches.</p>}
    </Panel>
  );
}
