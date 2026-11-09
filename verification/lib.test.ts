// Run with: node --test verification/

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  type Segment,
  lineCountsFromSegments,
  testRanges,
  commentOf,
  sectionsInComment,
  expandSections,
  citationsIn,
  docAbove,
  parseTlc,
  specSections,
  specExamples,
  xccovLines,
  normalisePath,
} from "./lib.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));

test("line counts follow llvm-cov's line rule", () => {
  // fn f() {        line 1, region entry, count 5
  //     if x {      line 2, region 2 enters at col 10 with count 1
  //         a();    line 3, inside region 2
  //     }           line 4, back to the outer region
  //                 line 5, a gap
  // }               line 6
  const segs: Segment[] = [
    [1, 1, 5, true, true, false],
    [2, 10, 1, true, true, false],
    [4, 6, 5, true, false, false],
    [5, 1, 0, true, true, true],
    [6, 1, 5, true, true, false],
    [6, 2, 0, false, false, false],
  ];
  const c = lineCountsFromSegments(segs);
  assert.equal(c.get(1), 5);
  assert.equal(c.get(2), 5); // wrapped 5, a region of 1 starts: the highest
  assert.equal(c.get(3), 1);
  assert.equal(c.get(4), 1); // wrapped count of region 2 at line start
  assert.equal(c.get(6), 5);
  assert.equal(c.has(7), false);
});

test("a skipped region is not code", () => {
  const segs: Segment[] = [
    [1, 1, 0, false, true, false],
    [3, 1, 0, false, false, false],
  ];
  const c = lineCountsFromSegments(segs);
  assert.equal(c.has(1), false);
  assert.equal(c.has(2), false);
});

test("test modules are found, braces in strings and comments skipped", () => {
  const src = [
    "fn real() {}", // 1
    "", // 2
    "#[cfg(test)]", // 3
    "mod tests {", // 4
    '    const S: &str = "}"; // }', // 5
    "    const C: char = '}';", // 6
    "    fn t<'a>(x: &'a str) {}", // 7
    "    /* } */", // 8
    '    const R: &str = r#"}"#;', // 9
    "}", // 10
    "#[cfg(kani)]", // 11
    "mod proofs;", // 12
    "fn after() {}", // 13
  ];
  assert.deepEqual(testRanges(src), [
    [3, 10],
    [11, 12],
  ]);
});

test("comments are found outside strings and URLs", () => {
  assert.equal(commentOf("let x = 1; // the count (7.1)"), " the count (7.1)");
  assert.equal(commentOf('let u = "https://example.org"; '), undefined);
  assert.equal(commentOf('let s = "// not a comment";'), undefined);
  assert.equal(commentOf("/// doc (2.3)"), "/ doc (2.3)");
});

test("section citations", () => {
  assert.deepEqual(sectionsInComment("the control characters of 2.3 (2.3)"), ["2.3"]);
  assert.deepEqual(sectionsInComment("parses (SPEC 3.1-3.3)"), ["3.1-3.3"]);
  assert.deepEqual(sectionsInComment("files (5.6, 12.11)"), ["5.6", "12.11"]);
  assert.deepEqual(sectionsInComment("see Section 2.2 for the verifier"), ["2.2"]);
  assert.deepEqual(sectionsInComment("(7.1 step 3)"), ["7.1"]);
  assert.deepEqual(sectionsInComment("rust (MSRV) is 1.95, x.y (not)"), []);
  assert.deepEqual(sectionsInComment("keepalive (11), the port is 7472 (15)"), ["11", "15"]);
  assert.deepEqual(sectionsInComment("an entry's type (SPEC 4.5, 15)"), ["4.5", "15"]);
  assert.deepEqual(sectionsInComment("may not send it (Section 13), and Section 14"), ["13", "14"]);
  assert.deepEqual(sectionsInComment("by up to an hour (12.10, D.4)"), ["12.10", "D.4"]);
  assert.deepEqual(sectionsInComment("a length (2 bytes), a pair (0, 1)"), ["0", "1"]);
  assert.deepEqual(sectionsInComment("RFC 9420 Section 12.4.3.2, (2.1.3)"), []);
  assert.deepEqual(expandSections(["3.1-3.3", "12.11"]), ["3.1", "3.2", "3.3", "12.11"]);
  assert.deepEqual(expandSections(["6.1-7.3"]), ["6.1", "7.3"]);
  assert.deepEqual(sectionsInComment("test vectors (B.1 to B.3), and (3.1 – 3.2)"), ["B.1-B.3", "3.1-3.2"]);
  assert.deepEqual(expandSections(["B.1-B.3"]), ["B.1", "B.2", "B.3"]);
  assert.deepEqual(citationsIn(["a", "// b (4.5)", 'c("(9.9)")'], 10), [{ line: 12, sections: ["4.5"] }]);
});

test("doc comments above a harness", () => {
  const lines = ["", "/// Checks the rule", "/// of 2.3 (2.3).", "#[kani::proof]", "#[kani::unwind(3)]", "fn harness() {}"];
  assert.equal(docAbove(lines, 6), "Checks the rule\nof 2.3 (2.3).");
});

test("TLC logs", () => {
  const pass = `Model checking completed. No error has been found.
  Estimates of the probability that TLC did not check all reachable states
3520112 states generated, 3,512,000 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 61.`;
  assert.deepEqual(parseTlc(pass, 0), { result: "pass", states: 3520112, distinct: 3512000, depth: 61 });

  const fail = `Error: Invariant NoMixedHistory is violated.
Error: The behavior up to this point is:
State 1: <Initial predicate>
State 2: <Join line 10>
State 14: <History line 99>
8,000 states generated, 2,000 distinct states found, 100 states left on queue.`;
  assert.deepEqual(parseTlc(fail, 12), {
    result: "violation",
    invariant: "NoMixedHistory",
    traceLength: 14,
    states: 8000,
    distinct: 2000,
  });

  const stopped = `Progress(31) at 2026-11-08: 9,000 states generated (1 s/min), 4,000 distinct states found, 300 states left on queue.`;
  assert.deepEqual(parseTlc(stopped, 124), { result: "stopped", states: 9000, distinct: 4000, depth: 31 });
});

test("spec sections and examples", () => {
  const spec = [
    "# Title",
    "## 2. Transport",
    "### 2.3. Lines",
    "```",
    "C: JOIN #a",
    "S: OK",
    "## not a heading in code",
    "C:\\Users",
    "```",
    "## Appendix B. Test Vectors",
    "```",
    "AUTH abc",
    "```",
  ].join("\n");
  assert.deepEqual(specSections(spec), [
    { num: "2", title: "Transport", depth: 1 },
    { num: "2.3", title: "Lines", depth: 2 },
    { num: "B", title: "Test Vectors", depth: 1 },
  ]);
  const ex = specExamples(spec);
  assert.deepEqual(ex.get("2.3"), { client: 1, server: 1 });
  assert.deepEqual(ex.get("B"), { client: 1, server: 0 });
});

test("xccov's archive JSON, from the fixture", () => {
  const json = JSON.parse(fs.readFileSync(path.join(HERE, "fixtures/xccov-archive.json"), "utf8"));
  const lines = xccovLines(json, (p) => normalisePath(p, "/elsewhere"));
  assert.deepEqual([...lines.keys()], ["clients/apple/Sources/Client/ChatClient.swift"]);
  assert.deepEqual(
    [...lines.get("clients/apple/Sources/Client/ChatClient.swift")!],
    [
      [2, 3],
      [3, 0],
      [4, 1],
    ],
  );
});

test("paths from tools", () => {
  assert.equal(normalisePath("/repo/crates/a/src/x.rs", "/repo"), "crates/a/src/x.rs");
  assert.equal(normalisePath("/home/runner/work/r/r/crates/a/src/x.rs", "/repo"), "crates/a/src/x.rs");
  assert.equal(normalisePath("crates/a/src/x.rs", "/repo"), "crates/a/src/x.rs");
  assert.equal(normalisePath("/home/u/.cargo/registry/src/index.crates.io-1/foo/src/lib.rs", "/repo"), undefined);
});
