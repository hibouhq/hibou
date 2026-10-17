# Hibou Press Toolkit

**hibou** is a self-hosted security intelligence platform for the whole SDLC.
**Tagline:** Eyes on what you ship.

Hibou is alpha software, not production-ready. Features may be incomplete and
breaking changes are expected. Do not imply production readiness or endorsement.

## Choose An Asset

| Use | File |
| --- | --- |
| Primary logo on white/light backgrounds | `logo-light.svg` or `logo-light.png` |
| Primary logo on dark backgrounds | `logo-dark.svg` or `logo-dark.png` |
| Stacked logo | `logo-stacked-light.svg`, `logo-stacked-dark.svg` |
| Mark without wordmark | `logomark-light.svg`, `logomark-dark.svg` |
| One-color reproduction | `logomark-black.svg`, `logomark-white.svg` |
| IDE toolbars at 24px | `toolbar-light.svg`, `toolbar-dark.svg` |
| IDE toolbars at 16px | `toolbar-16-light.svg`, `toolbar-16-dark.svg` |
| Browser favicon | `favicon.svg`, `favicon.ico`, `favicon-16.png`, `favicon-32.png` |
| Extension marketplace tile | `icon-128.png` |
| App/launcher icon | `icon.svg`, `icon-192.png`, `icon-512.png` |
| Social preview | `social-card.svg`, `social-card.png` |
| README/project banner | `readme-banner.svg` |

## Usage

- Use the solid mark for branding and the outline for IDE toolbars.
- At 16px use the optical cut, not a scaled full-detail logo. It deliberately
  omits pupils and beak and separates the eyes from the posts.
- Keep clear space of at least one eye diameter around the visible artwork.
- Keep the mark at least 24px tall, except for the dedicated 16px icons.
- Keep the horizontal lockup at least 128px wide. For smaller uses, use the mark.
- Preserve the H, ear tufts, and eyes below the crossbar. Do not move the eyes
  into the bar, stretch the logo, add shadows, or redraw the wordmark.
- Use light/dark variants on their intended backgrounds. Do not recolor the
  amber eyes or use amber as text on white.

## Colors And Type

- Hibou Blue: `#58A6FF` on dark; `#1F6FEB` on light.
- Owl Amber: `#FBBF24`; Night: `#0B0F1A`; text: `#E6EDF3` / `#161B22`.
- Wordmark: Space Grotesk Bold, converted to vector paths. No fonts are needed
  to display the distributed SVGs. The source font is licensed under SIL OFL;
  its license is included as `FONT-LICENSE.txt`.

The name and logos identify Hibou. This toolkit does not grant trademark rights
or imply that third-party products are affiliated with the project. Trademark
clearance has not been independently certified.

Source assets and regeneration instructions are in `brand/` in the
Hibou repository. Approved asset exports are checked in; the ZIP download is
generated during the docs build and is not versioned. Use `cd docs && npm ci &&
npm run brand` to regenerate assets. The generator also synchronizes a
checked-out `hibou-ide/` repository when present. `npm run build` packages the
approved toolkit for download without updating other repositories.
