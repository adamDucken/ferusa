import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const page = await readFile(new URL("../src/routes/+page.svelte", import.meta.url), "utf8");
const setup = await readFile(new URL("../src/lib/components/Setup.svelte", import.meta.url), "utf8");

function script(source, globals, expose) {
  const body = source.match(/<script lang="ts">([\s\S]*?)<\/script>/)[1]
    .replace(/^\s*import [\s\S]*?;/gm, "");
  const js = ts.transpile(body, { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None });
  return new Function(...Object.keys(globals), `${js}\nreturn { ${expose} };`)(...Object.values(globals));
}

const flush = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};

function mount(paired = false) {
  const document = { visibilityState: "visible" };
  const events = new Map();
  let onMount;
  const backend = {
    check_setup: () => paired,
    set_app_foreground: () => {},
    pending_request: () => null,
  };
  const state = script(page, {
    $state: (value) => value,
    document,
    window: { setTimeout() {}, clearTimeout() {}, setInterval() {}, clearInterval() {} },
    onMount: (callback) => { onMount = callback; },
    listen: async (event, callback) => { events.set(event, callback); return () => {}; },
    invoke: async (command) => backend[command](),
    formatInvokeError: String,
  }, "syncForegroundState, refreshSetup, onSetupComplete, onUnlocked, get screen() { return screen; }, get unlocked() { return isUnlocked; }");
  onMount();
  return { state, document, events, backend };
}

test("every initial enrollment step stays mounted through hide, expiry, and resume", async () => {
  const { state, document, events } = mount();
  await flush();
  const enrollment = script(setup, {
    $state: (value) => value,
    $props: () => ({ oncomplete() {} }),
    onMount() {},
  }, "setStep(value) { step = value; }, get step() { return step; }");
  for (const step of ["node-id", "pin4", "pin4-confirm", "pin6", "pin6-confirm", "verify-code", "pairing"]) {
    enrollment.setStep(step);
    document.visibilityState = "hidden";
    const hidden = state.syncForegroundState();
    assert.equal(state.screen, "setup", step);
    assert.equal(state.unlocked, false);
    events.get("ferusa://session-expired")();
    await hidden;
    await flush();
    assert.equal(state.screen, "setup", step);
    document.visibilityState = "visible";
    await state.syncForegroundState();
    assert.equal(state.screen, "setup", step);
    assert.equal(enrollment.step, step);
  }
});

test("paired app locks before background IPC finishes and resumes at biometrics", async () => {
  const { state, document, backend } = mount(true);
  await flush();
  state.onUnlocked();
  assert.equal(state.screen, "idle");
  const pending = deferred();
  backend.set_app_foreground = () => pending.promise;
  document.visibilityState = "hidden";
  const hidden = state.syncForegroundState();
  assert.equal(state.unlocked, false);
  assert.equal(state.screen, "biometric");
  state.onUnlocked();
  assert.equal(state.unlocked, false);
  pending.resolve();
  await hidden;
  document.visibilityState = "visible";
  await state.syncForegroundState();
  assert.equal(state.screen, "biometric");
});

test("stale setup checks cannot undo pairing completion or unlock", async () => {
  const { state, backend } = mount();
  await flush();
  const old = deferred();
  backend.check_setup = () => old.promise;
  const refresh = state.refreshSetup();
  state.onSetupComplete();
  state.onUnlocked();
  old.resolve(false);
  await refresh;
  assert.equal(state.screen, "idle");
  assert.equal(state.unlocked, true);
});

test("setup-changed rechecks storage and returns an unpaired app to enrollment", async () => {
  const { state, backend, events } = mount(true);
  await flush();
  backend.check_setup = () => false;
  events.get("ferusa://setup-changed")();
  await flush();
  assert.equal(state.screen, "setup");
  assert.equal(state.unlocked, false);
});
