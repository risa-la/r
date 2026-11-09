// The spec, section by section, with what checks each one: example lines
// the spec tests replay, the TLA+ model, Kani proofs, and the comments in
// code and tests that cite it.

import { DATA, fileUrl, useJson } from "./data";
import type { SpecData, SpecSection, Summary } from "./types";
import { Crumbs, Loading, NoResults } from "./ui";

export default function SpecView() {
  const spec = useJson<SpecData>(`${DATA}/spec.json`);
  const summary = useJson<Summary>(`${DATA}/summary.json`);
  if (spec.state === "loading" || summary.state === "loading") return <Loading />;
  const s = summary.state === "ready" ? summary.data : undefined;
  if (spec.state === "missing") {
    return (
      <section className="panel">
        <div className="panel-head">
          <Crumbs parts={[{ label: "verification", href: "/verification/" }, { label: "spec" }]} />
        </div>
        <div className="panel-body">
          <NoResults summary={undefined} />
        </div>
      </section>
    );
  }
  const data = spec.data;
  return (
    <section className="panel v-spec">
      <div className="panel-head">
        <Crumbs parts={[{ label: "verification", href: "/verification/" }, { label: "spec" }]} />
      </div>
      <div className="panel-body">
        <h1 className="v-title">by spec section</h1>
        <p className="v-lede">
          each section of the spec ({data.draft}) with what checks it. citations are comments in the code that name a
          section, such as (7.1).
        </p>
        {data.otherModels.length > 0 && (
          <p className="v-note">
            {data.otherModels.map((m) => `${m.title} models ${m.draft}`).join("; ")}, whose sections are numbered
            differently, so {data.otherModels.length === 1 ? "it is" : "they are"} not listed here.
          </p>
        )}
        <div className="v-spec-key label" aria-hidden="true">
          <span>
            <b className="badge ex">c / s</b> example lines, client / server
          </span>
          <span>
            <b className="badge tla">tla+</b> model
          </span>
          <span>
            <b className="badge kani">kani</b> proofs
          </span>
          <span>
            <b className="badge code">code</b> citations in code
          </span>
          <span>
            <b className="badge test">tests</b> citations in tests
          </span>
        </div>
      </div>
      <ul className="v-sections">
        {data.sections.map((sec) => (
          <SectionRow key={sec.num} sec={sec} summary={s} />
        ))}
      </ul>
    </section>
  );
}

function SectionRow({ sec, summary }: { sec: SpecSection; summary: Summary | undefined }) {
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
          <b className="badge ex" title={`${sec.examples.client} client and ${sec.examples.server} server example lines`}>
            {sec.examples.client} / {sec.examples.server}
          </b>
        )}
        {models.length > 0 && <b className="badge tla">tla+ {models.join(", ")}</b>}
        {proofs.length > 0 && <b className="badge kani">kani {proofs.length}</b>}
        {sec.code.length > 0 && <b className="badge code">code {sec.code.length}</b>}
        {sec.tests.length > 0 && <b className="badge test">tests {sec.tests.length}</b>}
      </span>
    </>
  );
  return (
    <li className={`depth-${sec.depth}`}>
      {expandable ? (
        <details>
          <summary className="row">{head}</summary>
          <div className="more">
            {proofs.length > 0 && (
              <Cites
                label="kani proofs"
                items={proofs.map((p) => ({ href: fileUrl(p.path, p.line), text: p.id, note: p.status === "success" ? "" : p.status }))}
              />
            )}
            {sec.code.length > 0 && (
              <Cites label="cited in code" items={sec.code.map(([p, l]) => ({ href: fileUrl(p, l), text: `${p}:${l}` }))} />
            )}
            {sec.tests.length > 0 && (
              <Cites label="cited in tests" items={sec.tests.map(([p, l]) => ({ href: fileUrl(p, l), text: `${p}:${l}` }))} />
            )}
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
