// Browser contract for the offline explanatory artifact; no live security calls.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);
const artifact = path.join(
  root,
  "docs/public/visuals/kepr-security/index.html",
);
await fs
  .access(artifact)
  .catch(() => assert.fail("The offline security flow artifact is missing"));
const { chromium } = await import(
  path.join(
    root,
    "target/kepr-visual-tools/node_modules/playwright-core/index.mjs",
  )
);
const html = await fs.readFile(artifact);
const server = http.createServer((req, res) => {
  if (req.url === "/") {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(html);
  } else {
    res.writeHead(404);
    res.end();
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
let browser;
try {
  browser = await chromium.launch({
    executablePath: "/usr/bin/chromium",
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-sync",
      "--no-first-run",
    ],
  });
  const page = await browser.newPage({
    viewport: { width: 1440, height: 1000 },
    reducedMotion: "reduce",
  });
  const errors = [],
    external = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/*", (route) => {
    if (route.request().url().startsWith(origin)) return route.continue();
    external.push(route.request().url());
    return route.abort();
  });
  await page.goto(origin);
  await page
    .getByRole("heading", { name: "Your agent. Your data. A controlled exit." })
    .waitFor();
  assert.equal(
    await page.getByTestId("mode-caption").textContent(),
    "Implemented source · protected-session boundary",
  );
  await page.getByRole("button", { name: "Controls to add" }).click();
  assert.equal(
    await page.getByTestId("mode-caption").textContent(),
    "Proposed design · capabilities still to implement",
  );
  await page.getByLabel("Example request").selectOption("confidential");
  assert.match(
    await page.getByTestId("outcome").textContent(),
    /local|blocked/i,
  );
  await page.getByLabel("Example request").selectOption("personal-mail");
  await page.getByRole("button", { name: "Approve demo action" }).click();
  assert.match(
    await page.getByTestId("outcome").textContent(),
    /blocked/i,
    "Human approval must not override a prohibited personal destination",
  );
  await page.getByLabel("Example request").selectOption("work-mail");
  assert.match(await page.getByTestId("outcome").textContent(), /waiting/i);
  await page.getByRole("button", { name: "Approve demo action" }).click();
  assert.match(await page.getByTestId("outcome").textContent(), /approved/i);
  await page.getByRole("button", { name: "How Kepr works" }).click();
  await page.getByLabel("Example request").selectOption("card");
  assert.match(
    await page.getByTestId("outcome").textContent(),
    /gap|unchanged|not covered/i,
  );
  await page.getByLabel("Example request").selectOption("browser");
  assert.match(
    await page.getByTestId("outcome").textContent(),
    /outside|unprotected/i,
  );
  await page.getByLabel("Example request").selectOption("summary");
  await page.getByRole("button", { name: "Next step" }).click();
  assert.match(
    await page.getByTestId("step-detail").textContent(),
    /Authenticate/i,
  );
  const beforeZoom = await page
    .locator('[data-testid="diagram"] .react-transform-component')
    .getAttribute("style");
  await page.getByRole("button", { name: "Zoom in" }).click();
  await page.waitForTimeout(400);
  assert.notEqual(
    await page
      .locator('[data-testid="diagram"] .react-transform-component')
      .getAttribute("style"),
    beforeZoom,
  );
  await page.getByRole("button", { name: "Reset zoom" }).click();
  const downloads = path.dirname(artifact);
  for (const [mode, button] of [
    ["current", "How Kepr works"],
    ["target", "Controls to add"],
  ]) {
    await page.getByRole("button", { name: button }).click();
    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "Download SVG" }).click();
    const download = await downloadPromise;
    const target = path.join(downloads, `kepr-${mode}-flow.svg`);
    await download.saveAs(target);
    const svg = await fs.readFile(target, "utf8");
    assert(
      !/<script|<foreignObject|https?:\/\//.test(
        svg.replace("http://www.w3.org/2000/svg", ""),
      ),
    );
    const imageHeight = Number(svg.match(/<svg[^>]* height="(\d+)"/)?.[1]);
    assert(
      Number.isFinite(imageHeight) && imageHeight > 0,
      "SVG has no bounded height",
    );
    const imagePage = await browser.newPage({
      viewport: { width: 980, height: imageHeight },
    });
    await imagePage.setContent(
      `<style>body{margin:0;background:#101715}img{display:block;width:980px}</style><img src="data:image/svg+xml;base64,${Buffer.from(svg).toString("base64")}">`,
    );
    await imagePage.locator("img").evaluate((img) => img.decode());
    await imagePage.screenshot({
      path: path.join(downloads, `kepr-${mode}-flow.png`),
      fullPage: true,
    });
    await imagePage.close();
  }
  await page.getByRole("button", { name: "How Kepr works" }).click();
  await page.getByLabel("Example request").selectOption("summary");
  await page.screenshot({
    path: path.join(downloads, "preview.png"),
    fullPage: true,
  });
  for (const width of [360, 768, 1024, 1280]) {
    await page.setViewportSize({ width, height: 1000 });
    await page.waitForTimeout(100);
    assert(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth + 1,
      ),
      `Horizontal overflow at ${width}px`,
    );
    if (width === 360)
      await page.screenshot({
        path: path.join(downloads, "mobile-preview.png"),
        fullPage: true,
      });
  }
  assert.deepEqual(errors, [], "Browser runtime errors");
  assert.deepEqual(external, [], "The artifact attempted an external request");
  console.log(
    "Visual checks passed: policy examples, controls, offline export, 4 viewports, no external requests.",
  );
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}
