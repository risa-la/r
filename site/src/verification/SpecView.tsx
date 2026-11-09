// The spec, section by section, with what checks each one: example lines
// the spec tests replay, the TLA+ model, Kani proofs, and the comments in
// code and tests that cite it. A section without subsections counts as
// checked when a test, an example line, a proof or a model covers it;
// citations in code alone do not count.

import { DATA, fileUrl, useJson } from "./data";
import type { SpecData, SpecSection, Summary } from "./types";
import { Frame } from "./Tree";
import { Crumbs, Hero, Loading } from "./ui";

const checked = (s: SpecSection) =>
  s.examples.client + s.examples.server > 0 || s.tests.length > 0 || s.kani.length > 0 || s.tla.length > 0;

/** The sections without subsections: headings that only group others are not counted. */
const leaves = (all: SpecSection[]) => all.filter((s, k) => !all[k + 1]?.num.startsWith(`${s.num}.`));

export default function SpecView() {
  const spec = useJson<SpecData>(`${DATA}/spec.json`);
  const summary = useJson<Summary>(`${DATA}/summary.json`);
  if (spec.state === "loading" || summary.state === "loading") return <Loading />;
  const s = summary.state === "ready" ? summary.data : undefined;
  const data = spec.state === "ready" ? spec.data : undefined;
  const counted = new Set(data ? leaves(data.sections) : []);
  return (
    <Frame summary={s}>
      <section className="panel v-spec">
      <div className="panel-head v-head">
        <Crumbs parts={[{ label: "verification", href: "/verification/" }, { label: "spec" }]} />
        {data && <span className="label">{data.draft}</span>}
      </div>
      <Hero
        tally={data && { covered: [...counted].filter(checked).length, total: counted.size }}
        label="sections checked"
        title="sections without subsections that a test, an example line, a kani proof or a tla+ model covers. citations in code alone do not count."
      />
      {data && (
        <ul className="v-sections">
          {data.sections.map((sec) => (
            <SectionRow key={sec.num} sec={sec} summary={s} unchecked={counted.has(sec) && !checked(sec)} />
          ))}
        </ul>
      )}
      </section>
    </Frame>
  );
}

function SectionRow({ sec, summary, unchecked }: { sec: SpecSection; summary: Summary | undefined; unchecked: boolean }) {
  const ex = sec.examples.client + sec.examples.server;
  const models = sec.tla.map((id) => summary?.tla.models.find((m) => m.id === id)?.title ?? id);
  const proofs = sec.kani.map((k) => summary?.kani[k]).filter((p) => p !== undefined);
  const expandable = sec.code.length + sec.tests.length + proofs.length > 0;
  const head = (
    <>
      <span className="num">{sec.num}</span>
      <span className="title">{sec.title}</span>
      <span className="badges">
        {ex > 0 && (
          <b className="badge ex" title={`${sec.examples.client} client, ${sec.examples.server} server`}>
            examples {ex}
          </b>
        )}
        {models.length > 0 && <b className="badge tla">tla+ {models.join(", ")}</b>}
        {proofs.length > 0 && <b className="badge kani">kani {proofs.length}</b>}
        {sec.tests.length > 0 && <b className="badge test">tests {sec.tests.length}</b>}
        {sec.code.length > 0 && (
          <b className="badge code" title="places in the code that cite it. not a check.">
            code {sec.code.length}
          </b>
        )}
      </span>
    </>
  );
  return (
    <li className={`depth-${sec.depth}${unchecked ? " none" : ""}`}>
      {expandable ? (
        <details>
          <summary className="row">{head}</summary>
          <div className="more">
            {proofs.length > 0 && (
              <Cites
                label="kani"
                items={proofs.map((p) => ({ href: fileUrl(p.path, p.line), text: p.id, note: p.status === "success" ? "" : p.status }))}
              />
            )}
            {sec.tests.length > 0 && <Cites label="tests" items={sec.tests.map(([p, l]) => ({ href: fileUrl(p, l), text: `${p}:${l}` }))} />}
            {sec.code.length > 0 && <Cites label="code" items={sec.code.map(([p, l]) => ({ href: fileUrl(p, l), text: `${p}:${l}` }))} />}
          </div>
        </details>
      ) : (
        <div className="row">{head}</div>
      )}
    </li>
  );
}

function Cites({ label, items }: { label: string; items: { href: string; text: string; note?: string }[] }) {
  return (
    <div className="cites">
      <span className="label">{label}</span>
      <ul>
        {items.map((it, k) => (
          <li key={k}>
            <a href={it.href}>{it.text}</a>
            {it.note && <span className="miss"> ({it.note})</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}
