import { defineCollection } from "astro:content";
import { glob } from "astro/loaders";
import { DOC_PATTERNS, docId } from "./docs";

const docs = defineCollection({
  loader: glob({
    base: "..",
    pattern: DOC_PATTERNS,
    generateId: ({ entry }) => docId(entry),
  }),
});

export const collections = { docs };
