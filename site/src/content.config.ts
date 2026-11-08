import { defineCollection } from "astro:content";
import { SPEC_DIR, SPEC_README_URL, stitchSpec } from "./spec";

// One document for now: the spec, stitched from the files of spec/.
const docs = defineCollection({
  loader: {
    name: "risala-spec",
    load: async ({ store, renderMarkdown, generateDigest, watcher }) => {
      const sync = async () => {
        const body = stitchSpec();
        store.clear();
        store.set({
          id: "spec",
          data: {},
          body,
          filePath: "../spec/README.md",
          digest: generateDigest(body),
          // Links resolve from spec/README.md, which sits beside the others.
          rendered: await renderMarkdown(body, { fileURL: SPEC_README_URL }),
        });
      };
      await sync();
      watcher?.add(SPEC_DIR);
      watcher?.on("change", (file) => {
        if (file.startsWith(SPEC_DIR)) void sync();
      });
    },
  },
});

export const collections = { docs };
