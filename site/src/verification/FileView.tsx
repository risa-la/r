// One source file, line by line, with every kind of evidence at once: a
// narrow stripe per layer beside the line number, and the line tinted by
// the strongest layer that reaches it (kani, then fuzzing, then
// integration tests, then unit tests). Lines that code coverage sees but
// nothing reaches are tinted red. Hovering (or tapping) a line shows what
// reaches it.

import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { ReactNode, SyntheticEvent } from "react";
import { DATA, LAYERS, type Layer, count, fileUrl, githubUrl, hasLayer, pct, ratio, readToggles, saveToggles, useJson } from "./data";
import { highlight } from "./highlight";
import { Frame } from "./Tree";
import type { FileData, LayerKey, LineEntry, Summary, Tally } from "./types";
import { Bar, Crumbs, Hero, Loading, NoResults } from "./ui";

type Toggles = Record<LayerKey, boolean>;

export default function FileView({ path }: { path: string }) {
  const summary = useJson<Summary>(`${DATA}/summary.json`);
  const file = useJson<FileData>(encodeURI(`${DATA}/files/${path}.json`));
  if (summary.state === "loading" || file.state === "loading") return <Loading />;
  const s = summary.state === "ready" ? summary.data : undefined;
  if (file.state === "missing") {
    return (
      <Frame summary={s} current={path}>
        <section className="panel">
          <div className="panel-head">
            <Crumbs parts={[{ label: "verification", href: "/verification/" }, { label: path }]} />
          </div>
          <p className="v-hero-foot label">
            <NoResults />
          </p>
        </section>
      </Frame>
    );
  }
  return (
    <Frame summary={s} current={path}>
      <Source file={file.data} summary={s} />
    </Frame>
  );
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

// A run of this many comment lines shows its first and last line only,
// until opened, so that a file opens on code rather than its docs.
const FOLD = 10;

/** The hidden middle of each long run of comment lines, as first and last line. */
function foldsOf(lines: string[]): [number, number][] {
  const out: [number, number][] = [];
  let start = 0;
  for (let k = 0; k <= lines.length; k++) {
    if (k < lines.length && /^\s*\/\//.test(lines[k])) continue;
    if (k - start >= FOLD) out.push([start + 2, k - 1]);
    start = k + 1;
  }
  return out;
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
  // Lines hidden from here on, for the row that stands for them.
  fold?: number;
}

const Line = memo(function Line({ n, text, html, stripes, tint, test, target, fold }: LineProps) {
  let cls = "ln";
  if (tint) cls += ` t-${tint}`;
  if (test) cls += " test";
  if (target) cls += " target";
  if (fold) cls += " fold";
  return (
    <div {...(fold ? { id: `F${n}`, "data-fold": n, title: `${n}-${n + fold - 1}` } : { id: `L${n}`, "data-n": n })} className={cls}>
      <span className="gut">
        {fold ? (
          <button type="button" className="num" aria-expanded="false" aria-label={`lines ${n} to ${n + fold - 1}`}>
            …
          </button>
        ) : (
          <a className="num" href={`#L${n}`}>
            {n}
          </a>
        )}
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
  const folds = useMemo(() => foldsOf(lines), [lines]);
  const [opened, setOpened] = useState<ReadonlySet<number>>(new Set());
  const open = (a: number) => setOpened((prev) => new Set(prev).add(a));
  // Closed folds by first hidden line. One the target falls in is open, and
  // stays so.
  const touches = useCallback((a: number, b: number) => !!target && target[0] <= b && target[1] >= a, [target]);
  const closed = useMemo(
    () => new Map(folds.filter(([a, b]) => !opened.has(a) && !touches(a, b))),
    [folds, opened, touches],
  );
  useEffect(() => {
    for (const [a, b] of folds) if (touches(a, b)) open(a);
  }, [folds, touches]);
  // A line to scroll to once its fold has opened.
  const pending = useRef<number | null>(null);
  useEffect(() => {
    if (pending.current === null) return;
    document.getElementById(`L${pending.current}`)?.scrollIntoView({ block: "center" });
    pending.current = null;
  }, [closed]);
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
    const fold = (e.target as Element).closest("[data-fold]");
    if (fold) {
      setPinned(null);
      return open(Number(fold.getAttribute("data-fold")));
    }
    if ((e.target as Element).closest("a")) return;
    const n = lineAt(e.target);
    if (n !== null) setPinned((p) => (p === n ? null : n));
  };

  const rows = useMemo(() => {
    const out: ReactNode[] = [];
    for (let k = 0; k < lines.length; k++) {
      const end = closed.get(k + 1);
      out.push(
        <Line
          key={k}
          n={k + 1}
          text={lines[k]}
          html={html[k]}
          stripes={stripes[k]}
          tint={tints[k]}
          test={tests[k]}
          target={!!target && k + 1 >= target[0] && k + 1 <= target[1]}
          fold={end && end - k}
        />,
      );
      if (end) k = end - 1;
    }
    return out;
  }, [lines, html, stripes, tints, tests, target, closed]);

  // A line's row, or the row of the fold that hides it.
  const rowOf = (n: number) => {
    const fold = [...closed].find(([a, b]) => n >= a && n <= b);
    return document.getElementById(fold ? `F${fold[0]}` : `L${n}`);
  };
  const nextMiss = () => {
    if (!misses.length) return;
    // The first one below the middle of the window, wrapping round.
    const mid = innerHeight / 2;
    const n = misses.find((m) => (rowOf(m)?.getBoundingClientRect().top ?? 0) > mid) ?? misses[0];
    location.hash = `#L${n}`;
    const el = document.getElementById(`L${n}`);
    if (el) el.scrollIntoView({ block: "center" });
    else pending.current = n;
  };

  const entry = summary?.files.find((f) => f.path === file.path);
  const commit = summary?.commit ?? null;
  const shown = pinned ?? hover;
  const offClasses = LAYERS.filter((l) => !on[l.key])
    .map((l) => `off-${l.short}`)
    .join(" ");

  return (
    <>
      <section className="panel">
        <div className="panel-head v-head">
          <Crumbs parts={[{ label: "verification", href: "/verification/" }, { label: file.crate }]} />
          <a href={githubUrl(commit, file.path)}>github ↗</a>
        </div>
        <h1 className="v-path">{file.path}</h1>
        {file.test ? (
          <p className="v-hero-foot label">test code, not counted</p>
        ) : (
          <Hero tally={entry?.tally.any} label="lines checked" title="code lines a unit test, integration test, fuzz input or kani proof reaches." />
        )}
        <div className="v-toggles" role="group" aria-label="Layers">
          {layers.map((l) => (
            <LayerToggle key={l.key} layer={l} on={on[l.key]} onClick={() => toggle(l.key)} has={hasLayer(summary, l.key, file.lang)} tally={entry?.tally[l.key]} />
          ))}
          {measured && (
            <button className="button v-next" type="button" onClick={nextMiss} disabled={!misses.length} title="the next line nothing reaches">
              {misses.length ? `↓ ${count(misses.length)} unreached` : "✓ 0 unreached"}
            </button>
          )}
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

function LayerToggle({ layer, on, onClick, has, tally }: { layer: Layer; on: boolean; onClick: () => void; has: boolean; tally: Tally | undefined }) {
  // The TLA+ model checks the spec, not the code: no share of lines. Nor
  // does a layer without data here.
  const lines = layer.key !== "tla";
  return (
    <button type="button" className="v-toggle" aria-pressed={on} onClick={onClick} title={layer.tip} style={{ ["--c" as string]: layer.color }}>
      <span className="sw" aria-hidden="true" />
      <span className="name">{layer.label}</span>
      {lines && has && ratio(tally) !== undefined && (
        <>
          <Bar tally={tally} color={layer.color} />
          <span className="val">{pct(tally)}</span>
        </>
      )}
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

  const none = <span className="dim">-</span>;
  const miss = <span className="miss">✗</span>;
  const hits = (v: number | undefined, has: boolean) => (!has || v === undefined ? none : v > 0 ? <strong>✓ {count(v)}</strong> : miss);

  const fuzz = entry?.f;
  const proofs = entry?.k ?? [];
  const missed = entry?.km ?? [];
  const models = summary?.tla.models.filter((m) => entry?.t?.some((s) => m.sections.includes(s))) ?? [];

  return (
    <div ref={ref} className={`v-details${pinned ? " pinned" : ""}`} role={pinned ? "dialog" : "tooltip"} aria-label={`line ${n}`}>
      <div className="dh">
        <strong>line {n}</strong>
        {(test || filled) && <span className="label">not counted</span>}
        {pinned && (
          <button type="button" className="close" onClick={onClose} aria-label="Close">
            ×
          </button>
        )}
      </div>
      <dl>
        <Row layer={LAYERS[0]}>{hits(entry?.u, hasLayer(summary, "unit", swift ? "swift" : "rust"))}</Row>
        {!swift && (
          <>
            <Row layer={LAYERS[1]}>{hits(entry?.i, hasLayer(summary, "integration"))}</Row>
            <Row layer={LAYERS[2]}>
              {!hasLayer(summary, "fuzz") || fuzz === undefined
                ? none
                : fuzz.length
                  ? fuzz.map((t) => summary?.fuzz[t]).filter(Boolean).map((t) => `${t!.crate}/${t!.target}`).join(", ")
                  : miss}
            </Row>
            <Row layer={LAYERS[3]}>
              {!hasLayer(summary, "kani") || !(proofs.length || missed.length) ? (
                none
              ) : (
                <>
                  <ProofList ids={proofs} summary={summary} pinned={pinned} />
                  {missed.length > 0 && (
                    <div className="sub" title="covered the region, missed this line">
                      <span className="miss">✗ </span>
                      <ProofList ids={missed} summary={summary} pinned={pinned} />
                    </div>
                  )}
                </>
              )}
            </Row>
            <Row layer={LAYERS[4]}>
              {!hasLayer(summary, "tla") || !entry?.t?.length
                ? none
                : `§${entry.t.join(" §")}${models.length ? ` · ${models.map((m) => m.title).join(", ")}` : ""}`}
            </Row>
          </>
        )}
      </dl>
    </div>
  );
}

function Row({ layer, children }: { layer: Layer; children: ReactNode }) {
  return (
    <div className="dr" style={{ ["--c" as string]: layer.color }}>
      <dt title={layer.tip}>
        <span className="sw" aria-hidden="true" />
        {layer.label}
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
            {p.coverage === "function" && <span className="dim" title="function-level coverage, approximate"> ≈</span>}
          </li>
        );
      })}
    </ul>
  );
}
