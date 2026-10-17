<!-- markdownlint-disable MD033 MD041 -->
<div align="center">
  <img src="./logo.svg" alt="Hibou" height="72" />
  <h1>Hibou — Brand Book</h1>
  <p><em>Eyes on what you ship.</em></p>
</div>

---

> **Hibou** (French for *owl*) is the open security intelligence platform that
> watches over your entire software lifecycle. This document is the single
> source of truth for how Hibou looks, sounds, and feels.

## Table of contents

1. [Brand strategy](#1-brand-strategy)
2. [Brand story](#2-brand-story)
3. [Personality, archetype & voice](#3-personality-archetype--voice)
4. [Audience](#4-audience)
5. [Taglines & messaging](#5-taglines--messaging)
6. [Visual identity direction](#6-visual-identity-direction)
7. [Logo](#7-logo)
8. [Color palette](#8-color-palette)
9. [Typography](#9-typography)
10. [Iconography & illustration](#10-iconography--illustration)
11. [UI design language](#11-ui-design-language)
12. [Do's and don'ts](#12-dos-and-donts)
13. [Asset index](#13-asset-index)

---

## 1. Brand strategy

### Positioning statement

> For platform, security, and developer teams who are drowning in disconnected
> scanners and SBOM noise, **Hibou** is the open security intelligence platform
> that unifies dependency risk, code findings, PR analysis, and release impact
> into one watchful view. Unlike point tools that bolt onto a single stage,
> Hibou sees the **whole software lifecycle** — and it's open source, so you
> own it.

### Mission

Give every team a single, trustworthy pair of eyes on the security of their
software — from the first dependency to the final release — without lock-in.

### Vision

A world where supply-chain security is open, continuous, and boring: risk is
caught in the dark long before it reaches production, and no team has to choose
between visibility and ownership.

### Core values

| Value | What it means in practice |
|-------|---------------------------|
| **Vigilance** | Always watching. Continuous, proactive, never "scan and forget". |
| **Clarity** | Signal over noise. No FUD, no vanity metrics — only what matters. |
| **Openness** | Open source, open standards (SBOM, VEX, SARIF), open data. |
| **Trust** | Accurate, explainable, auditable. We earn confidence, not fear. |
| **Developer-first** | Meets engineers where they work: PRs, IDEs, CLI, config-as-code. |

### Brand archetype

**The Sage**, guarding the gate as a **Guardian**.
The owl is the classic symbol of wisdom and night vision — it sees what others
miss and acts with quiet precision. Hibou is the calm expert on the wall, not
the alarm that cries wolf.

---

## 2. Brand story

Owls hunt at night. They see what the daylight hides, they move in silence, and
they miss nothing. Modern software has the same problem as a dark forest: the
threats are real, they're moving, and most tools only light up one tree at a
time.

**Hibou** is the owl on the branch above your software supply chain. It watches
every dependency, every commit, every release — merging the findings that
today live in a dozen disconnected scanners into one clear, calm view. It works
while you sleep, it tells you only what you need to know, and because it's open
source, it answers to you.

Wisdom over alarm. Sight over noise. **Eyes on what you ship.**

---

## 3. Personality, archetype & voice

### Personality

Vigilant · Sharp · Calm · Trustworthy · Open · Technical-but-approachable.

Hibou is the senior security engineer everyone trusts: deeply technical, never
condescending, never panicked. Confident enough to stay quiet until it matters.

### Brand voice guidelines

- **Clear, not clever.** Say the true thing in the fewest words.
- **Calm, not alarmist.** We surface risk; we never sell fear. Avoid
  "catastrophic", "hackers are coming", red-everything dashboards.
- **Precise, like a good tool.** Use exact terms (CVE, VEX, reachability, SBOM)
  but always make them legible to a newcomer.
- **Warm, like an OSS community.** First person plural ("we"), generous docs,
  credit contributors.
- **Show, don't hype.** Prefer a code block or a screenshot over an adjective.

**Voice cheat-sheet**

| Instead of… | Say… |
|-------------|------|
| "Revolutionary AI-powered security." | "Find reachable vulnerabilities, automatically." |
| "Protect your enterprise from catastrophic breaches." | "Catch supply-chain risk before it ships." |
| "Best-in-class synergy." | "One view of dependency, code, and release risk." |

---

## 4. Audience

| Persona | Role | What they need from Hibou |
|---------|------|---------------------------|
| **Priya — Platform / DevSecOps engineer** | Owns CI/CD and the security toolchain | One self-hostable system instead of five SaaS scanners; config-as-code; clean APIs. |
| **Marco — Application developer** | Ships features daily | PR gates that aren't noisy, clear "is this reachable?" answers, fast CLI. |
| **Dana — Security lead / auditor** | Owns risk posture & compliance | Org-wide visibility, VEX management, ISO 27001 mapping, immutable audit log. |
| **Sam — Self-hosting / OSS enthusiast** | Runs their own stack | A single binary, a Helm chart, no telemetry, real open source. |

---

## 5. Taglines & messaging

**Primary tagline**

> **Eyes on what you ship.**

**Alternates (by context)**

- *Security that never sleeps.* — ops / reliability framing
- *See what others miss.* — intelligence / detection framing
- *The night watch for your software supply chain.* — narrative framing
- *Wisdom for your supply chain.* — sage framing

**Elevator pitch (one sentence)**

> Hibou is an open-source security intelligence platform that unifies dependency
> risk, code findings, PR analysis, and release impact into a single
> multi-tenant view.

**Boilerplate (for footers / READMEs)**

> Hibou is an open security intelligence platform for the software lifecycle. It
> ingests SBOMs, scans for vulnerabilities, secrets and malware, analyzes
> reachability, and gates pull requests — all from a single self-hostable
> binary.

---

## 6. Visual identity direction

Hibou's world is **twilight**: the moment between day and night when the owl
wakes up. The system pairs a deep night-sky base with a single, unmistakable
**amber owl-eye** accent — the spark of attention in the dark.

- **Mood:** nocturnal, focused, precise, quietly premium.
- **Signature move:** the *owl eyes* — two amber **aperture eyes** (iris + dark
  pupil) peering from beneath the brow of the H, reading as eyes and a scanning
  lens at once.
- **Contrast:** mostly calm dark surfaces, with amber reserved for the one thing
  that deserves attention (the eyes, a CTA, an alert).

We avoid: corporate gradients-on-white, shield-and-padlock clichés, neon
hacker-green, and busy "cyber" backgrounds.

---

## 7. Logo

The Hibou mark is an **H-owl monogram**: a bold capital **H** whose two verticals
slope outward at the top into **ear tufts**, the crossbar reads as the **brow**,
and two **amber aperture eyes** (iris + dark pupil) with a small **beak** sit in
the lower counter. The letter and the animal are the same shape — a wordless,
ownable mark that reads as both an *H* and an owl. It works at favicon size and
as a single-color sticker.

### Variants (in `brand/`)

| File | Use |
|------|-----|
| `logo.svg` | Primary horizontal lockup (mark + wordmark). Default everywhere. |
| `logomark.svg` | Mark only. App header, avatars, favicons, stickers. |
| `favicon.svg` | Dedicated solid optical cut for 16px and retina displays. |
| `icon.svg` | Solid square tile for extension listings and apps. |
| `toolbar-outline.svg` | Monochrome outline for IDE toolbars at 24px. |
| `toolbar-outline-16.svg` | Monochrome optical outline for 16px toolbars. |
| `press-kit/` | Approved light/dark logos, outlined wordmarks, SVG/PNG/ICO exports, usage notes. |
| `social-card.svg` | 1280×640 GitHub/OG social preview. |
| `readme-banner.svg` | Wide README header banner. |

### Clear space & sizing

- Keep clear space of at least **one eye diameter** around the visible artwork.
- Minimum sizes: full-detail logomark **24px**, horizontal lockup **128px** wide.
- At **16px**, use the optical asset: two pixel-aligned eyes, no pupils or beak.
- Use **solid** for primary branding and **outline** for monochrome IDE toolbars.

### Construction

The mark lives on a 64 grid. The two verticals of the **H** are bold bars whose
outer-top edges slope up into pointed **ear tufts**; the **crossbar** is the
brow. In the lower counter sit two **aperture eyes** — an amber iris with a dark
pupil, the brand's signature — and a small amber **beak** below them. Everything
is built from straight edges, rectangles, triangles, and circles, so it stays
crisp at its intended sizes. At 16px the dedicated optical cut uses pixel-aligned
posts and two clear eye blocks (no beak or pupil). The monochrome optical cut
widens the face opening so eyes do not merge with posts. Do not simply scale
the full-detail logo to 16px.

---

## 8. Color palette

Hibou's palette extends the existing app surface tokens (GitHub-dark family) so
the brand and product feel like one thing.

### Core

| Token | HEX | Use |
|-------|-----|-----|
| **Night** | `#0B0F1A` | Deepest background, social cards, hero. |
| **Surface** | `#0D1117` | App background. |
| **Surface Raised** | `#161B22` | Cards, headers. |
| **Surface Overlay** | `#1C2128` | Popovers, insets. |
| **Border** | `#30363D` | Dividers, outlines. |
| **Text** | `#E6EDF3` | Primary text on dark. |
| **Text Muted** | `#8B949E` | Secondary text. |

### Brand

| Token | HEX | Use |
|-------|-----|-----|
| **Hibou Blue** (primary) | `#58A6FF` | Links, primary actions, focus. |
| **Hibou Blue Deep** | `#3B82F6` | Gradients, pressed states. |
| **Vigil Cyan** | `#22D3EE` | Twilight gradient pair, highlights. |
| **Owl Amber** (signature) | `#FBBF24` | The eyes. Sparing accent: one per view. |
| **Amber Deep** | `#F59E0B` | Amber pressed / borders. |

**Twilight gradient:** `#22D3EE → #3B82F6 → #0B0F1A` (used in hero / banner).

### Severity & status (product, unchanged)

| Token | HEX |
|-------|-----|
| Critical | `#F85149` |
| High | `#E6550D` |
| Medium | `#D29922` |
| Low | `#8B949E` |
| OK / Pass | `#3FB950` |
| Info | `#58A6FF` |

> ⚠️ **Amber discipline:** Owl Amber is the brand's signature. Use it for the
> logo eyes and at most one focal accent per screen. It must never be confused
> with the *medium-severity* product color — in product UI, severity colors win.

---

## 9. Typography

All three typefaces are open-source and free to bundle.

| Role | Typeface | Notes |
|------|----------|-------|
| **Display / wordmark** | **Space Grotesk** | Geometric, a little character. Headings, hero, the "hibou" wordmark (lowercase). |
| **UI / body** | **Inter** | Already used in the app. All product UI and long-form text. |
| **Code / mono** | **JetBrains Mono** | Code blocks, CLI snippets, data. |

### Rules

- The wordmark is always **lowercase**: `hibou`.
- Headings: Space Grotesk, tight tracking (`-0.02em`), weights 500–700.
- Body: Inter, 400/500, line-height 1.6.
- Never stretch, condense, or outline type. Never set the wordmark in a serif.

See `brand/typography.css` for ready-to-use CSS custom properties.

---

## 10. Iconography & illustration

- **Icon set:** Lucide (already used in the app). Stroke-based, 1.5–2px,
  rounded joins. Keep icons monochrome (Text or Text Muted); reserve color for
  meaning (severity, status).
- **Illustration:** geometric, low-detail, built from the same primitives as
  the logo. Think constellations, scanning lenses, and the owl silhouette — not
  3D renders or stock "hacker in a hoodie".
- **Motion:** calm and purposeful. Eyes can "blink"/scan on load; avoid
  bouncing, flashing, or anything alarmist.

---

## 11. UI design language

- **Dark-first.** The product is a dark dashboard; the brand assumes dark
  surfaces. Light mode, if added, keeps amber as the only warm accent.
- **Calm density.** Information-dense but breathable: generous line-height,
  clear hierarchy, one focal accent per view.
- **Rounded geometry.** Radii `0.5–0.75rem` for controls, `0.75–1rem` for cards
  — echoing the geometric build of the mark.
- **Tokens, not hex.** Always reference `color-tokens.json` /
  Tailwind tokens; never hard-code colors in components.

### Accessibility & light mode

- **Dark-first, light soon.** The brand ships dark mode first; a light theme is
  planned. On dark, the mark's `#58A6FF` (~7:1 on Night) and `#FBBF24` (~11:1)
  clear WCAG 1.4.11 non-text contrast (≥3:1) with margin.
- **Light-mode swaps.** On light backgrounds, use a darker blue for the
  letterform (`#1F6FEB`/`#0969DA`, ≥4.5:1 on white) and a deeper amber
  (`#B45309`) for any amber *text*; the eye's dark pupil keeps the amber iris
  legible on light. Keep amber as the only warm accent in both themes.
- **Never color-alone.** Meaning is carried by shape and text, not hue, so the UI
  and mark survive greyscale and color-blindness. Every logo SVG ships with
  `role="img"`, a `<title>`, and an `aria-label`.

---

## 12. Do's and don'ts

**Do**

- ✅ Use the owl mark on dark surfaces with breathing room.
- ✅ Keep amber rare and intentional — it's the eyes.
- ✅ Write calm, precise, jargon-aware copy.
- ✅ Pair the logo with the lowercase `hibou` wordmark.

**Don't**

- ❌ Recolor the mark in arbitrary colors or add gradients to the eyes.
- ❌ Put the logo on busy photos or low-contrast backgrounds.
- ❌ Use padlock/shield-with-keyhole clichés or neon "cyber" backdrops.
- ❌ Capitalize the wordmark (`HIBOU`) or set it in serif.
- ❌ Use Owl Amber as a generic UI accent or confuse it with medium severity.

---

## 13. Asset index

| Asset | Path |
|-------|------|
| Brand book | `brand/brand-guidelines.md` |
| Primary logo | `brand/logo.svg` |
| Logomark | `brand/logomark.svg` |
| Favicon | `brand/favicon.svg` |
| Social / OG card | `brand/social-card.svg` |
| README banner | `brand/readme-banner.svg` |
| Color tokens | `brand/color-tokens.json` |
| Typography CSS | `brand/typography.css` |
| Press toolkit | `brand/press-kit/` |

---

<div align="center"><sub>Hibou — Eyes on what you ship. Open source, self-hostable, vigilant.</sub></div>
