import { defineConfig } from "astro/config";
import { satteri } from "@astrojs/markdown-satteri";
import { docLinks } from "./src/lib/doc-links";

export default defineConfig({
  site: "https://risa.la",
  markdown: {
    // Protocol lines read best as plain text in the site's own colors.
    syntaxHighlight: false,
    processor: satteri({ mdastPlugins: [docLinks] }),
  },
});
