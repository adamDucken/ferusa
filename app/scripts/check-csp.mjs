import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const configPath = path.join(root, "src-tauri", "tauri.conf.json");
const srcDir = path.join(root, "src");

const failures = [];

function fail(message) {
  failures.push(message);
}

function directiveValues(csp, directive) {
  const value = csp?.[directive];
  if (Array.isArray(value)) return value;
  if (typeof value === "string") return value.split(/\s+/).filter(Boolean);
  return [];
}

function hasSource(csp, directive, source) {
  return directiveValues(csp, directive).includes(source);
}

function requireSource(csp, directive, source) {
  if (!hasSource(csp, directive, source)) {
    fail(`production CSP ${directive} must include ${source}`);
  }
}

function forbidSource(csp, directive, source) {
  if (hasSource(csp, directive, source)) {
    fail(`production CSP ${directive} must not include ${source}`);
  }
}

async function* walk(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walk(fullPath);
    } else {
      yield fullPath;
    }
  }
}

const config = JSON.parse(await readFile(configPath, "utf8"));
const csp = config?.app?.security?.csp;

if (!csp || csp === null) {
  fail("production CSP must be enabled in src-tauri/tauri.conf.json");
} else {
  requireSource(csp, "default-src", "'self'");
  requireSource(csp, "script-src", "'self'");
  requireSource(csp, "style-src", "'self'");
  requireSource(csp, "connect-src", "ipc:");
  requireSource(csp, "connect-src", "http://ipc.localhost");
  requireSource(csp, "object-src", "'none'");
  requireSource(csp, "base-uri", "'none'");
  requireSource(csp, "form-action", "'none'");
  requireSource(csp, "script-src-attr", "'none'");
  requireSource(csp, "style-src-attr", "'none'");

  forbidSource(csp, "script-src", "'unsafe-inline'");
  forbidSource(csp, "script-src", "'unsafe-eval'");
  forbidSource(csp, "style-src", "'unsafe-inline'");
}

const dangerousDisable =
  config?.app?.security?.dangerousDisableAssetCspModification ??
  config?.app?.security?.["dangerous-disable-asset-csp-modification"];
if (dangerousDisable === true) {
  fail("Tauri asset CSP modification must remain enabled");
}

const forbiddenPatterns = [
  { pattern: "{@html", label: "Svelte raw HTML rendering" },
  { pattern: "innerHTML", label: "DOM innerHTML writes" },
  { pattern: "outerHTML", label: "DOM outerHTML writes" },
  { pattern: "insertAdjacentHTML", label: "DOM insertAdjacentHTML writes" },
  { pattern: "eval(", label: "eval execution" },
  { pattern: "new Function", label: "Function constructor execution" },
  { pattern: "document.write", label: "document.write execution" },
];

const scannedExtensions = new Set([".html", ".js", ".svelte", ".ts"]);

for await (const file of walk(srcDir)) {
  if (!scannedExtensions.has(path.extname(file))) continue;

  const content = await readFile(file, "utf8");
  const relative = path.relative(root, file);

  if (content.includes("style=")) {
    fail(`${relative} contains an inline style attribute`);
  }

  for (const { pattern, label } of forbiddenPatterns) {
    if (content.includes(pattern)) {
      fail(`${relative} contains ${label}: ${pattern}`);
    }
  }
}

if (failures.length > 0) {
  console.error("CSP regression check failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("CSP regression check passed.");
