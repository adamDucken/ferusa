import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const readSource = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("pairing replacement never invokes destructive reset", async () => {
  const [replacement, page, backend] = await Promise.all([
    readSource("../src/lib/components/Reset.svelte"),
    readSource("../src/routes/+page.svelte"),
    readSource("../src-tauri/src/lib.rs"),
  ]);

  assert.match(replacement, /authorize_pairing_replacement/);
  assert.doesNotMatch(replacement, /invoke\("reset_setup"/);
  assert.match(page, /onauthorized=\{onReplacementAuthorized\}/);
  assert.doesNotMatch(backend, /commands::reset_setup/);
});

test("setup distinguishes initial enrollment from safe replacement", async () => {
  const setup = await readSource("../src/lib/components/Setup.svelte");

  assert.match(setup, /mode === "replacement" \? "ferusa pair" : "ferusa init"/);
  assert.match(setup, /Do not clear the current phone or desktop pairing/);
});

test("replacement copy preserves the old factor until durable commit", async () => {
  const replacement = await readSource("../src/lib/components/Reset.svelte");

  assert.match(replacement, /current phone share stays active/i);
  assert.match(replacement, /failure before commit leaves the current pairing and vault usable/i);
  assert.doesNotMatch(replacement, /vault on the desktop is not affected/i);
});
