# Site

The risala website and documentation, built with [Astro](https://astro.build).

```sh
npm install
npm run dev      # http://localhost:4321
npm run build    # static site in dist/
npm run check    # type-check
```

## Documents

The site publishes the spec straight from `spec/` in the repository; there
is no copy here. `src/spec.ts` stitches its files into one page,
`spec/README.md` first and the rest in name order, and `/spec.md` serves the
same text as one file to download. `PLAN.md` and `docs/plans` are for coding
agents and stay off the site. `src/docs.ts` holds the spec's title and page
order. Links into `spec/` become links to their section on the spec page, and
links to any other repository file point at GitHub (`src/lib/doc-links.ts`).
The spec's version comes from its header block.

## Look

The site follows the Apple client's terminal design
(`apple/terminal-foundations`): the same palette roles with light and dark
values, JetBrains Mono throughout, framed panels with a `risala / place`
breadcrumb, and Hudhud for rare states such as the 404 page. The colors and
metrics live in `src/styles/global.css`; keep them in step with
`clients/apple/Resources/Assets.xcassets/Palette` and `Layout.swift`.

Document pages are laid out like Oxide's RFD site: a header with the title
and a metadata row, the body at a 80-column measure, and a contents sidebar
that marks the current section. Press `/` or Cmd/Ctrl-K anywhere to jump to
a document or section.

## Deploying

`.github/workflows/site.yml` builds the site and publishes it to GitHub Pages
on every push to `main` that touches `site/` or `spec/`. Pull requests
build without publishing.

The custom domain is set in the repository's Settings → Pages, not with a
`CNAME` file, which Pages ignores when a workflow publishes. With `risa.la`
as the custom domain and a `www` CNAME record pointing at
`risa-la.github.io`, Pages redirects `www.risa.la` to `risa.la` by itself.
