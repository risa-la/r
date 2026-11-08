// The whole spec as one Markdown file, for reading offline or printing.
import { stitchSpec } from "../spec";

export function GET() {
  return new Response(stitchSpec(), {
    headers: { "Content-Type": "text/markdown; charset=utf-8" },
  });
}
