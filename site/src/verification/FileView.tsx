// One source file, line by line, with every kind of evidence at once: a
// narrow stripe per layer beside the line number, and the line tinted by
// the strongest layer that reaches it (kani, then fuzzing, then
// integration tests, then unit tests). Lines that code coverage sees but
// nothing reaches are tinted red. Hovering (or tapping) a line shows what
// reaches it.

import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { ReactNode, SyntheticEvent } from "react";
import {
  DATA,
  LAYERS,
  REPO_URL,
  type Layer,
  count,
  date,
  fileUrl,
  githubUrl,
  hasLayer,
  pct,
  readToggles,
  saveToggles,
  useJson,
} from "./data";
import { highlight } from "./highlight";
import type { FileData, LayerKey, LineEntry, Summary } from "./types";
import { Bar, Crumbs, Loading, NoResults } from "./ui";

type Toggles = Record<LayerKey, boolean>;

export default function FileView({ path }: { path: string }) {
  const summary = useJson<Summary>(`${DATA}/summary.json`);
  const file = useJson<FileData>(encodeURI(`${DATA}/files/${path}.json`));
  if (summary.state === "loading" || file.state === "loading") return <Loading />;
  if (file.state === "missing") {
    return (
      <section className="panel">
        <div className="panel-head">
          <Crumbs parts={[{ label: "verification", href: "/verification/" }, { label: path }]} />
        </div>
        <div className="panel-body">
          <NoResults summary={undefined} />
        </div>
      </section>
    );
  }
  return <Source file={file.data} summary={summary.state === "ready" ? summary.data : undefined} />;
}

// Per line, the state of each stripe, in LAYERS order: h reached, m seen
// but not reached, p a proof covered the region but missed the line, or
// empty when that tool does not see the line.
function stripesOf(e: LineEntry | undefined): string[] {
  if (!e) return ["", "", "", "", ""];
  const hm = (v: number | undefined) => (v === undefined ? "" : v > 0 ? "h" : "m");
  return [
    hm(e.u),
    hm(e.i),
    e.f === undefined ? "" : e.f.length ? "h" : "m",
    e.k?.length ? "h" : e.km?.length ? "p" : "",
    e.t?.length ? "h" : "",
  ];
}

// Lines inside a function that are not code themselves (a closing brace,
// `} else {`, a comment, a blank line) take the look of the code around
// them, so that a function reads as one block rather than broken stripes.
// Per layer, a gap counts as reached when the code on both sides is (or
// the one side, at a function's edge). Filled lines are only drawn: they
// are not counted, not searched as unreached, and the details say so.
function fillGaps(file: FileData, count: number): { shown: (LineEntry | undefined)[]; filled: boolean[] } {
  const shown: (LineEntry | undefined)[] = [];
  const filled: boolean[] = [];
  for (let n = 1; n <= count; n++) {
    shown.push(file.lines[n]);
    filled.push(false);
  }
  for (const [a, b] of file.blocks ?? []) {
    const anchors: number[] = [];
    for (let n = a; n <= b; n++) if (file.lines[n]) anchors.push(n);
    if (!anchors.length) continue;
    let k = 0;
    for (let n = a; n <= Math.min(b, count); n++) {
      if (file.lines[n]) {
        while (k < anchors.length && anchors[k] <= n) k++;
        continue;
      }
      const before = k > 0 ? file.lines[anchors[k - 1]] : undefined;
      const after = k < anchors.length ? file.lines[anchors[k]] : undefined;
      shown[n - 1] = merge(before, after);
      filled[n - 1] = true;
    }
  }
  return { shown, filled };
}

/** What a gap between two lines shows: what both show, or the one side. */
function merge(x: LineEntry | undefined, y: LineEntry | undefined): LineEntry {
  if (!x || !y) return { ...(x ?? y) };
  const num = (p: number | undefined, q: number | undefined) =>
    p === undefined ? q : q === undefined ? p : Math.min(p, q);
  const list = (p: number[] | undefined, q: number[] | undefined) =>
    p === undefined ? q : q === undefined ? p : p.filter((v) => q.includes(v));
  const out: LineEntry = {};
  const u = num(x.u, y.u);
  const i = num(x.i, y.i);
  const f = list(x.f, y.f);
  const k = list(x.k, y.k);
  if (u !== undefined) out.u = u;
  if (i !== undefined) out.i = i;
  if (f !== undefined) out.f = f;
  if (k?.length) out.k = k;
  if (x.t?.length && y.t?.length) out.t = x.t;
  return out;
}

// The tint ladder. TLA+ is not on it: the model checks the spec, not this
// code.
const LADDER: [LayerKey, keyof LineEntry][] = [
  ["kani", "k"],
  ["fuzz", "f"],
  ["integration", "i"],
  ["unit", "u"],
];

function reached(e: LineEntry, key: keyof LineEntry): boolean {
  const v = e[key];
  return Array.isArray(v) ? v.length > 0 : typeof v === "number" && v > 0;
}

/** The tint class: the strongest layer that reaches the line, or x for none. */
function tintOf(e: LineEntry | undefined, on: Toggles, test: boolean): string {
  if (!e || test) return "";
  for (const [layer, key] of LADDER) if (on[layer] && reached(e, key)) return key;
  // Only lines that coverage counts as code can be "not reached"; a proof's
  // region alone can span comments.
  const code = e.u !== undefined || e.i !== undefined || e.f !== undefined;
  return code ? "x" : "";
}

function parseHash(): [number, number] | undefined {
  const m = location.hash.match(/^#L(\d+)(?:-L?(\d+))?$/);
  if (!m) return undefined;
  const a = Number(m[1]);
  const b = m[2] ? Number(m[2]) : a;
  return [Math.min(a, b), Math.max(a, b)];
}

interface LineProps {
  n: number;
  text: string;
  html: string | undefined;
  stripes: string[];
  tint: string;
  test: boolean;
  target: boolean;
}

const Line = memo(function Line({ n, text, html, stripes, tint, test, target }: LineProps) {
  let cls = "ln";
  if (tint) cls += ` t-${tint}`;
  if (test) cls += " test";
  if (target) cls += " target";
  return (
    <div id={`L${n}`} data-n={n} className={cls}>
      <span className="gut">
        <a className="num" href={`#L${n}`}>
          {n}
        </a>
        <span className="stripes" aria-hidden="true">
          {stripes.map((s, k) => (
            <span key={k} className={`s s-${LAYERS[k].short} ${s}`} />
          ))}
        </span>
      </span>
      {html !== undefined ? (
        <code className="src" dangerouslySetInnerHTML={{ __html: html }} />
      ) : (
        <code className="src">{text}</code>
      )}
    </div>
  );
});

function Source({ file, summary }: { file: FileData; summary: Summary | undefined }) {
  const lines = useMemo(() => {
    const l = file.source.split("\n");
    if (l.at(-1) === "") l.pop();
    return l;
  }, [file]);
  const isTest = useCallback(
    (n: number) => file.test || file.testRanges.some(([a, b]) => n >= a && n <= b),
    [file],
  );
  const tests = useMemo(() => lines.map((_, k) => isTest(k + 1)), [lines, isTest]);
  const { shown: display, filled } = useMemo(() => fillGaps(file, lines.length), [file, lines]);
  const stripes = useMemo(() => display.map((e) => stripesOf(e)), [display]);
  const swift = file.lang === "swift";
  // The Swift client has unit tests only; its other columns would always be empty.
  const layers = swift ? LAYERS.filter((l) => l.key === "unit") : LAYERS;

  const [on, setOn] = useState<Toggles>(readToggles);
  const toggle = (key: LayerKey) =>
    setOn((prev) => {
      const next = { ...prev, [key]: !prev[key] };
      saveToggles(next);
      return next;
    });
  const tints = useMemo(() => display.map((e, k) => tintOf(e, on, tests[k])), [display, on, tests]);
  const misses = useMemo(() => tints.flatMap((t, k) => (t === "x" && !filled[k] ? [k + 1] : [])), [tints, filled]);
  const measured = useMemo(
    () => Object.values(file.lines).some((e) => e.u !== undefined || e.i !== undefined || e.f !== undefined),
    [file],
  );

  // Plain text first, then the highlighted lines as they come.
  const [html, setHtml] = useState<(string | undefined)[]>([]);
  useEffect(() => {
    let stop = false;
    setHtml([]);
    highlight(
      lines,
      file.lang,
      (start, chunk) =>
        setHtml((prev) => {
          const next = prev.slice();
          chunk.forEach((h, k) => (next[start + k] = h));
          return next;
        }),
      () => stop,
    ).catch(() => {
      // Without colours the plain text stays, which reads fine.
    });
    return () => {
      stop = true;
    };
  }, [lines, file.lang]);

  // #L12 and #L12-L20 mark lines; the browser looked for them before they
  // existed, so scroll once they do.
  const [target, setTarget] = useState(parseHash);
  useEffect(() => {
    const onHash = () => setTarget(parseHash());
    addEventListener("hashchange", onHash);
    const t = parseHash();
    if (t) document.getElementById(`L${t[0]}`)?.scrollIntoView({ block: "center" });
    return () => removeEventListener("hashchange", onHash);
  }, []);

  const [hover, setHover] = useState<number | null>(null);
  const [pinned, setPinned] = useState<number | null>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setPinned(null);
    addEventListener("keydown", onKey);
    return () => removeEventListener("keydown", onKey);
  }, []);
  const lineAt = (el: EventTarget | null) => {
    const row = (el as Element | null)?.closest?.("[data-n]");
    return row ? Number(row.getAttribute("data-n")) : null;
  };
  const onOver = (e: SyntheticEvent) => {
    const n = lineAt(e.target);
    if (n !== hover) setHover(n);
  };
  const onClick = (e: SyntheticEvent) => {
    if ((e.target as Element).closest("a")) return;
    const n = lineAt(e.target);
    if (n !== null) setPinned((p) => (p === n ? null : n));
  };

  const rows = useMemo(
    () =>
      lines.map((text, k) => (
        <Line
          key={k}
          n={k + 1}
          text={text}
          html={html[k]}
          stripes={stripes[k]}
          tint={tints[k]}
          test={tests[k]}
          target={!!target && k + 1 >= target[0] && k + 1 <= target[1]}
        />
      )),
    [lines, html, stripes, tints, tests, target],
  );

  const nextMiss = () => {
    if (!misses.length) return;
    // The first one below the middle of the window, wrapping round.
    const mid = innerHeight / 2;
    const n =
      misses.find((m) => (document.getElementById(`L${m}`)?.getBoundingClientRect().top ?? 0) > mid) ?? misses[0];
    location.hash = `#L${n}`;
    document.getElementById(`L${n}`)?.scrollIntoView({ block: "center" });
  };

  const entry = summary?.files.find((f) => f.path === file.path);
  const commit = summary?.commit ?? null;
  const shown = pinned ?? hover;
  const offClasses = LAYERS.filter((l) => !on[l.key])
    .map((l) => `off-${l.short}`)
    .join(" ");

  return (
    <>
      <section className="panel v-file-head">
        <div className="panel-head">
          <Crumbs parts={[{ label: "verification", href: "/verification/" }, { label: "src" }]} />
        </div>
        <div className="panel-body">
          <h1 className="v-path">{file.path}</h1>
          <dl className="v-meta">
            <div>
              <dt className="label">{swift ? "client" : "crate"}</dt>
              <dd>{file.crate}</dd>
            </div>
            <div>
              <dt className="label">lines</dt>
              <dd>{count(lines.length)}</dd>
            </div>
            <div>
              <dt className="label">results for</dt>
              <dd>
                {commit ? (
                  <a href={`${REPO_URL}/commit/${commit}`}>{commit.slice(0, 10)}</a>
                ) : (
                  "-"
                )}
                {summary?.generated ? ` · ${date(summary.generated)}` : ""}
              </dd>
            </div>
            <div>
              <dt className="label">source</dt>
              <dd>
                <a href={githubUrl(commit, file.path)}>github{commit ? "" : " (main)"}</a>
              </dd>
            </div>
          </dl>
          {file.test && <p className="v-note">this whole file is test code: it is shown muted and left out of the percentages.</p>}
          <NoResults summary={summary} lang={file.lang} />
        </div>
      </section>

      <section className="panel v-legend-panel">
        <div className="v-legend">
          <div className="v-toggles" role="group" aria-label="Layers">
            {layers.map((l) => (
              <LayerToggle key={l.key} layer={l} on={on[l.key]} onClick={() => toggle(l.key)} value={entry ? pct(entry.tally[l.key]) : "-"} has={hasLayer(summary, l.key, file.lang)} tally={entry?.tally[l.key]} />
            ))}
          </div>
          <div className="v-legend-key label">
            <span>
              <i className="key s-h" /> reached
            </span>
            <span>
              <i className="key s-m" /> code, not reached
            </span>
            {!swift && (
              <span>
                <i className="key s-p" /> proof covered the region, missed the line
              </span>
            )}
            <span>
              <i className="key row-x" /> nothing reaches it
            </span>
            <span>
              <i className="key row-test" /> test code
            </span>
          </div>
          <p className="v-legend-text">
            one stripe per layer beside the line number. the line is tinted by the strongest layer that reaches it: kani,
            then fuzzing, then integration, then unit tests.
            {!swift && " the tla+ stripe marks functions that cite a spec section the model covers: the model checks the spec, not this code."}{" "}
            hover or tap a line for details.
          </p>
          <div className="v-legend-actions">
            <button className="button" type="button" onClick={nextMiss} disabled={!misses.length}>
              {misses.length ? `next of ${count(misses.length)} unreached ↓` : measured ? "no unreached lines" : "no coverage to search"}
            </button>
          </div>
        </div>
      </section>

      <section className={`panel v-code ${offClasses}`}>
        <div className="v-code-scroll" onMouseOver={onOver} onMouseLeave={() => setHover(null)} onClick={onClick} onFocus={onOver}>
          <div className={`v-rows${swift ? " swift" : ""}`}>{rows}</div>
        </div>
        {shown !== null && (
          <Details
            n={shown}
            entry={file.lines[shown]}
            filled={filled[shown - 1]}
            test={tests[shown - 1]}
            summary={summary}
            swift={swift}
            pinned={pinned !== null}
            onClose={() => setPinned(null)}
          />
        )}
      </section>
    </>
  );
}

function LayerToggle({ layer, on, onClick, value, has, tally }: { layer: Layer; on: boolean; onClick: () => void; value: string; has: boolean; tally: { covered: number; total: number } | undefined }) {
  return (
    <button type="button" className="v-toggle" aria-pressed={on} onClick={onClick} style={{ ["--c" as string]: layer.color }}>
      <span className="sw" aria-hidden="true" />
      <span className="name">{layer.label}</span>
      {layer.key !== "tla" && <Bar tally={tally} color={layer.color} />}
      <span className="val">{has ? value : "no results"}</span>
    </button>
  );
}

function Details({
  n,
  entry,
  filled,
  test,
  summary,
  swift,
  pinned,
  onClose,
}: {
  n: number;
  entry: LineEntry | undefined;
  filled: boolean;
  test: boolean;
  summary: Summary | undefined;
  swift: boolean;
  pinned: boolean;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  // Just below the line, inside the code panel.
  useLayoutEffect(() => {
    const row = document.getElementById(`L${n}`);
    if (row && ref.current) ref.current.style.top = `${row.offsetTop + row.offsetHeight + 4}px`;
  }, [n]);

  const hits = (v: number | undefined, has: boolean) =>
    !has ? <span className="dim">no results</span> : v === undefined ? <span className="dim">not code it measures</span> : v > 0 ? <strong>{count(v)} hits</strong> : <span className="miss">not reached</span>;

  const fuzz = entry?.f;
  const proofs = entry?.k ?? [];
  const missed = entry?.km ?? [];
  const models = summary?.tla.models.filter((m) => entry?.t?.some((s) => m.sections.includes(s))) ?? [];

  return (
    <div ref={ref} className={`v-details${pinned ? " pinned" : ""}`} role={pinned ? "dialog" : "tooltip"} aria-label={`line ${n}`}>
      <div className="dh">
        <strong>line {n}</strong>
        {test && <span className="label">test code, not counted</span>}
        {filled && !test && <span className="label">not code: drawn like the code around it, not counted</span>}
        {pinned && (
          <button type="button" className="close" onClick={onClose} aria-label="Close">
            ×
          </button>
        )}
      </div>
      <dl>
        <Row layer={LAYERS[0]} label={swift ? "swift unit tests" : "unit tests"}>
          {hits(entry?.u, hasLayer(summary, "unit", swift ? "swift" : "rust"))}
        </Row>
        {!swift && (
          <>
            <Row layer={LAYERS[1]}>{hits(entry?.i, hasLayer(summary, "integration"))}</Row>
            <Row layer={LAYERS[2]}>
              {!hasLayer(summary, "fuzz") ? (
                <span className="dim">no results</span>
              ) : fuzz === undefined ? (
                <span className="dim">not in a fuzzed binary</span>
              ) : fuzz.length ? (
                fuzz.map((t) => summary?.fuzz[t]).filter(Boolean).map((t) => `${t!.crate}/${t!.target}`).join(", ")
              ) : (
                <span className="miss">no target reaches it</span>
              )}
            </Row>
            <Row layer={LAYERS[3]}>
              {!hasLayer(summary, "kani") ? (
                <span className="dim">no results</span>
              ) : proofs.length || missed.length ? (
                <>
                  <ProofList ids={proofs} summary={summary} pinned={pinned} />
                  {missed.length > 0 && (
                    <div className="sub">
                      <span className="label">covered the region, missed this line:</span>
                      <ProofList ids={missed} summary={summary} pinned={pinned} />
                    </div>
                  )}
                </>
              ) : (
                <span className="dim">no proof reaches it</span>
              )}
            </Row>
            <Row layer={LAYERS[4]}>
              {!hasLayer(summary, "tla") ? (
                <span className="dim">no results</span>
              ) : entry?.t?.length ? (
                <>
                  sections {entry.t.join(", ")}
                  {models.length > 0 && ` · model ${models.map((m) => m.title).join(", ")}`}
                  <div className="sub label">the model checks the spec, not this code.</div>
                </>
              ) : (
                <span className="dim">no modelled section cited</span>
              )}
            </Row>
          </>
        )}
      </dl>
      {!pinned && <div className="hint label">click to pin</div>}
    </div>
  );
}

function Row({ layer, label, children }: { layer: Layer; label?: string; children: ReactNode }) {
  return (
    <div className="dr" style={{ ["--c" as string]: layer.color }}>
      <dt>
        <span className="sw" aria-hidden="true" />
        {label ?? layer.label}
      </dt>
      <dd>{children}</dd>
    </div>
  );
}

function ProofList({ ids, summary, pinned }: { ids: number[]; summary: Summary | undefined; pinned: boolean }) {
  return (
    <ul className="proofs">
      {ids.map((k) => {
        const p = summary?.kani[k];
        if (!p) return null;
        return (
          <li key={k}>
            {pinned ? <a href={fileUrl(p.path, p.line)}>{p.id}</a> : p.id}
            {p.status !== "success" && <span className="miss"> ({p.status})</span>}
            {p.coverage === "function" && <span className="dim"> (function-level, approximate)</span>}
          </li>
        );
      })}
    </ul>
  );
}
