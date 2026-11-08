// Syntax colours for source files, by Shiki in the browser. Everything is
// loaded on first use: the core, the JavaScript regex engine (no WASM), and
// only the grammar the file needs. Token colours are CSS variables
// (--shiki-*, set in verification.css from the site's own colours), so they
// follow the theme toggle without highlighting again.

import type { HighlighterCore, ThemedToken } from "shiki/core";

export type Lang = "rust" | "swift";

const THEME = "risala";
let core: Promise<HighlighterCore> | undefined;

async function highlighter(lang: Lang): Promise<HighlighterCore> {
  core ??= (async () => {
    const [{ createHighlighterCore, createCssVariablesTheme }, { createJavaScriptRegexEngine }] = await Promise.all([
      import("shiki/core"),
      import("shiki/engine/javascript"),
    ]);
    return createHighlighterCore({
      themes: [createCssVariablesTheme({ name: THEME, variablePrefix: "--shiki-", fontStyle: true })],
      langs: [],
      engine: createJavaScriptRegexEngine(),
    });
  })();
  const h = await core;
  if (!h.getLoadedLanguages().includes(lang)) {
    await h.loadLanguage(lang === "rust" ? import("shiki/langs/rust.mjs") : import("shiki/langs/swift.mjs"));
  }
  return h;
}

const escape = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

// Shiki's FontStyle flags.
const ITALIC = 1;
const BOLD = 2;

function lineHtml(tokens: ThemedToken[]): string {
  let out = "";
  for (const t of tokens) {
    const text = escape(t.content);
    if (!t.color || t.color === "var(--shiki-foreground)") {
      if (!t.fontStyle) {
        out += text;
        continue;
      }
    }
    let style = t.color ? `color:${t.color}` : "";
    if (t.fontStyle && t.fontStyle & ITALIC) style += ";font-style:italic";
    if (t.fontStyle && t.fontStyle & BOLD) style += ";font-weight:700";
    out += `<span style="${style}">${text}</span>`;
  }
  return out;
}

const CHUNK = 250;

const idle = (): Promise<void> =>
  new Promise((resolve) => {
    if ("requestIdleCallback" in window) requestIdleCallback(() => resolve(), { timeout: 120 });
    else setTimeout(resolve, 16);
  });

/**
 * Highlights `lines` a chunk at a time, between frames, so a 4,000-line file
 * does not freeze the page. Each chunk goes to `onChunk` as HTML per line.
 * Stops early when `cancelled()` turns true.
 */
export async function highlight(
  lines: string[],
  lang: Lang,
  onChunk: (start: number, html: string[]) => void,
  cancelled: () => boolean,
): Promise<void> {
  const h = await highlighter(lang);
  let state: ReturnType<HighlighterCore["getLastGrammarState"]> | undefined;
  for (let start = 0; start < lines.length; start += CHUNK) {
    await idle();
    if (cancelled()) return;
    const tokens = h.codeToTokensBase(lines.slice(start, start + CHUNK).join("\n"), {
      lang,
      theme: THEME,
      grammarState: state,
      // Very long lines (generated data) stay plain rather than stall.
      tokenizeMaxLineLength: 2000,
    });
    state = h.getLastGrammarState(tokens);
    onChunk(start, tokens.map(lineHtml));
  }
}
