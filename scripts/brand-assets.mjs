import { createRequire } from "node:module";
import { readFile, writeFile, mkdir, copyFile, access, readdir, utimes, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { execFileSync } from "node:child_process";

const root = fileURLToPath(new URL("../", import.meta.url));
const require = createRequire(join(root, "docs/package.json"));
const sharp = require("sharp");
const fontkit = require("fontkit");
const brand = join(root, "brand");
const kit = join(brand, "press-kit");
const font = fontkit.openSync(join(brand, "fonts/SpaceGrotesk-Bold.woff2"));
const colors = { blue: "#58a6ff", lightBlue: "#1f6feb", night: "#0b0f1a", ink: "#161b22", white: "#e6edf3" };

if (process.argv.includes("--archive-only")) {
    await buildArchive();
    console.log("Generated docs/public/hibou-press-kit.zip");
    process.exit(0);
}

async function put(path, content) {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, content);
}

function fixed(svg, color) {
    return svg.replace(/<style>[\s\S]*?<\/style>/g, "").replace(/class="(?:body|mark)"/g, `fill="${color}"`).replace(/[\t ]+$/gm, "");
}

function content(svg) {
    return svg.replace(/^[\s\S]*?<svg\b[^>]*>/, "").replace(/<\/svg>\s*$/, "").replace(/<(title|desc)\b[^>]*>[\s\S]*?<\/\1>/g, "").replace(/[\t ]+$/gm, "").trim();
}

function svg(width, height, title, body) {
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="img" aria-label="${title}">${body}</svg>\n`;
}

function lettering(text, size, x, baseline, color) {
    const run = font.layout(text);
    let pen = 0;
    const paths = run.glyphs.map((glyph, index) => {
        const position = run.positions[index];
        const path = `<path d="${glyph.path.toSVG()}" transform="translate(${pen + position.xOffset} ${position.yOffset})"/>`;
        pen += position.xAdvance;
        return path;
    }).join("");
    const scale = size / font.unitsPerEm;
    return { width: pen * scale, markup: `<g fill="${color}" transform="translate(${x} ${baseline}) scale(${scale} ${-scale})">${paths}</g>` };
}

const mark = await readFile(join(brand, "logomark.svg"), "utf8");
const tile = await readFile(join(brand, "icon.svg"), "utf8");
const tiny = await readFile(join(brand, "favicon.svg"), "utf8");
const toolbar = await readFile(join(brand, "toolbar-outline.svg"), "utf8");
const toolbarTiny = await readFile(join(brand, "toolbar-outline-16.svg"), "utf8");
const darkMark = fixed(mark, colors.blue);
const lightMark = fixed(mark, colors.lightBlue);

const assets = new Map([
    ["logomark-light.svg", lightMark],
    ["logomark-dark.svg", darkMark],
    ["logomark-black.svg", fixed(mark, "#000000").replace(/fill="#[\da-f]{6}"/gi, 'fill="#000000"')],
    ["logomark-white.svg", fixed(mark, "#ffffff").replace(/fill="#[\da-f]{6}"/gi, 'fill="#ffffff"')],
    ["icon.svg", tile],
    ["favicon.svg", tiny],
    ["toolbar-light.svg", fixed(toolbar, "#374151")],
    ["toolbar-dark.svg", fixed(toolbar, colors.white)],
    ["toolbar-16-light.svg", fixed(toolbarTiny, "#374151")],
    ["toolbar-16-dark.svg", fixed(toolbarTiny, colors.white)],
]);

for (const [theme, symbol, foreground] of [["light", lightMark, colors.ink], ["dark", darkMark, colors.white]]) {
    const word = lettering("hibou", 64, 88, 70, foreground);
    const horizontal = svg(Math.ceil(96 + word.width), 96, "Hibou", `<g transform="translate(8 16) scale(.25)">${content(symbol)}</g>${word.markup}`);
    assets.set(`logo-${theme}.svg`, horizontal);
    const stackedWord = lettering("hibou", 56, 0, 292, foreground);
    const centeredWord = lettering("hibou", 56, (256 - stackedWord.width) / 2, 292, foreground);
    assets.set(`logo-stacked-${theme}.svg`, svg(256, 320, "Hibou", content(symbol) + centeredWord.markup));
    const standalone = lettering("hibou", 64, 8, 70, foreground);
    assets.set(`wordmark-${theme}.svg`, svg(Math.ceil(16 + standalone.width), 96, "Hibou", standalone.markup));
}

await put(join(brand, "logo.svg"), assets.get("logo-dark.svg"));
const tagline = lettering("Eyes on what you ship.", 40, 80, 470, colors.white).markup;
const social = svg(1280, 640, "Hibou: Eyes on what you ship", `<rect width="1280" height="640" fill="${colors.night}"/><g transform="translate(64 112) scale(3)">${content(assets.get("logo-dark.svg"))}</g>${tagline}`);
const banner = svg(1280, 320, "Hibou: Eyes on what you ship", `<rect width="1280" height="320" fill="${colors.night}"/><g transform="translate(48 64) scale(1.8)">${content(assets.get("logo-dark.svg"))}</g>${lettering("Eyes on what you ship.", 34, 580, 176, colors.white).markup}`);
assets.set("social-card.svg", social);
assets.set("readme-banner.svg", banner);
await put(join(brand, "social-card.svg"), social);
await put(join(brand, "readme-banner.svg"), banner);

for (const [name, data] of assets) await put(join(kit, name), data);
for (const name of ["logo-light", "logo-dark", "logo-stacked-light", "logo-stacked-dark", "logomark-light", "logomark-dark"]) {
    await put(join(kit, `${name}.png`), await sharp(Buffer.from(assets.get(`${name}.svg`))).resize({ width: name.startsWith("logo-") ? 1200 : 512 }).png().toBuffer());
}
await put(join(kit, "social-card.png"), await sharp(Buffer.from(social)).png().toBuffer());
for (const size of [128, 192, 512]) await put(join(kit, `icon-${size}.png`), await sharp(Buffer.from(tile)).resize(size, size).png().toBuffer());
for (const size of [16, 32]) await put(join(kit, `favicon-${size}.png`), await sharp(Buffer.from(tiny)).resize(size, size, { kernel: "nearest" }).png().toBuffer());
await copyFile(join(brand, "fonts/OFL.txt"), join(kit, "FONT-LICENSE.txt"));

const icoImages = await Promise.all([16, 32].map(size => readFile(join(kit, `favicon-${size}.png`))));
const icoHeader = Buffer.alloc(6 + 16 * icoImages.length);
icoHeader.writeUInt16LE(1, 2);
icoHeader.writeUInt16LE(icoImages.length, 4);
let icoOffset = icoHeader.length;
for (const [index, image] of icoImages.entries()) {
    const offset = 6 + 16 * index;
    icoHeader[offset] = icoHeader[offset + 1] = [16, 32][index];
    icoHeader.writeUInt16LE(1, offset + 4);
    icoHeader.writeUInt16LE(32, offset + 6);
    icoHeader.writeUInt32LE(image.length, offset + 8);
    icoHeader.writeUInt32LE(icoOffset, offset + 12);
    icoOffset += image.length;
}
await put(join(kit, "favicon.ico"), Buffer.concat([icoHeader, ...icoImages]));

for (const surface of ["site/public", "docs/public"]) {
    const target = join(root, surface);
    await put(join(target, "favicon.svg"), tiny);
    await copyFile(join(kit, "favicon.ico"), join(target, "favicon.ico"));
    await copyFile(join(kit, "favicon-16.png"), join(target, "favicon-16.png"));
    await copyFile(join(kit, "favicon-32.png"), join(target, "favicon-32.png"));
    for (const size of [192, 512]) await copyFile(join(kit, `icon-${size}.png`), join(target, `icon-${size}.png`));
    await put(join(target, "logomark.svg"), surface.startsWith("site") ? darkMark : mark);
    await put(join(target, "site.webmanifest"), JSON.stringify({ name: "Hibou", short_name: "hibou", icons: [192, 512].map(size => ({ src: `icon-${size}.png`, sizes: `${size}x${size}`, type: "image/png" })), theme_color: colors.night, background_color: colors.night, display: "standalone" }, null, 2) + "\n");
}
await put(join(root, "docs/src/assets/logomark.svg"), mark);
await mkdir(join(root, "docs/public/brand"), { recursive: true });
for (const name of ["logo-light.svg", "logo-dark.svg", "logomark-light.svg", "logomark-dark.svg"]) await copyFile(join(kit, name), join(root, "docs/public/brand", name));
await copyFile(join(kit, "social-card.png"), join(root, "docs/public/brand/social-card.png"));

const landingPath = join(root, "docs/landing.html");
let landing = await readFile(landingPath, "utf8");
landing = landing.replace(/<defs>\s*<g id="owl"[\s\S]*?<\/defs>/, `<defs><g id="owl" transform="scale(.25)">${content(darkMark)}</g></defs>`);
landing = landing.replace(/<link rel="icon"[\s\S]*?\/>/, `<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,${Buffer.from(tiny).toString("base64")}" />`);
const walkthrough = await readFile(join(root, "docs/images/readme/walkthrough.gif"));
landing = landing.replace(/data-animation="[^"]*"/, `data-animation="data:image/gif;base64,${walkthrough.toString("base64")}"`);
await put(landingPath, landing);

try {
    await access(join(root, "hibou-ide/vscode/package.json"));
    const extension = join(root, "hibou-ide");
    await copyFile(join(kit, "icon-128.png"), join(extension, "vscode/media/hibou-solid.png"));
    await put(join(extension, "vscode/media/hibou-outline.svg"), fixed(toolbar, "#c5c5c5"));
    await rm(join(extension, "vscode/media/icon.png"), { force: true });
    await rm(join(extension, "vscode/media/owl.svg"), { force: true });
    for (const [name, color] of [["hibou.svg", "#374151"], ["hibou_dark.svg", colors.white]]) await put(join(extension, "jetbrains/src/main/resources/icons", name), fixed(toolbarTiny, color));
    const pluginIcon = svg(40, 40, "Hibou", `<g transform="scale(.15625)">${content(tile)}</g>`);
    await put(join(extension, "jetbrains/src/main/resources/META-INF/pluginIcon.svg"), pluginIcon);
    await put(join(extension, "jetbrains/src/main/resources/META-INF/pluginIcon_dark.svg"), pluginIcon);
} catch (error) {
    if (error.code !== "ENOENT") throw error;
    console.log("IDE repository absent; extension assets remain available in press kit.");
}

async function buildArchive() {
    const archive = join(root, "docs/public/hibou-press-kit.zip");
    const files = (await readdir(kit)).sort();
    const timestamp = new Date("2000-01-01T00:00:00Z");
    for (const name of files) await utimes(join(kit, name), timestamp, timestamp);
    await mkdir(dirname(archive), { recursive: true });
    await rm(archive, { force: true });
    execFileSync("zip", ["-q", "-X", archive, ...files], { cwd: kit });
}

await buildArchive();
console.log(`Generated ${assets.size} SVG masters, outlined wordmarks, PNG/ICO exports, web assets, IDE assets, and docs/public/hibou-press-kit.zip`);
