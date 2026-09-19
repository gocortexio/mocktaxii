# Vendored third-party assets

These files are served directly by MockTAXII rather than fetched from a CDN, so
the admin interface renders correctly on a host with no internet access and no
page reaches an external origin. Each is redistributed under its own licence,
unchanged except where noted.

MockTAXII itself is AGPL-3.0-or-later; none of the licences below conflict with
redistributing these files alongside it.

## Bootstrap 5.3.0

`bootstrap.min.css`, `bootstrap.bundle.min.js`

Copyright 2011-2023 The Bootstrap Authors. Licensed under the MIT Licence.
https://github.com/twbs/bootstrap/blob/main/LICENSE

Both files are the upstream 5.3.0 release with one change: the trailing
`sourceMappingURL` comment was removed from each. The `.map` files it named
are not vendored, so the reference resolved to a 404 on this origin. Nothing
else in either file was touched.

## Font Awesome Free 6.4.0

`../../templates/_icons.svg.html`

The 29 solid icons this interface renders, extracted from the project's own
`sprites/solid.svg` and renamed with an `i-` prefix. No icon artwork is
modified.

Copyright 2023 Fonticons, Inc. Icons are licensed CC BY 4.0.
https://fontawesome.com/license/free

## Barlow

`fonts/barlow-400.woff2`, `barlow-500.woff2`, `barlow-600.woff2`,
`barlow-700.woff2`

Copyright The Barlow Project Authors. Licensed under the SIL Open Font
Licence 1.1. https://fonts.google.com/specimen/Barlow

The woff2 files are the latin subset as served by the Google Fonts API;
`fonts.css` is that API's own `@font-face` output with the remote URLs
rewritten to these local paths.
