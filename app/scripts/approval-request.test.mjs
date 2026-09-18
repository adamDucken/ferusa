import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const page = await readFile(new URL("../src/routes/+page.svelte", import.meta.url), "utf8");
const approve = await readFile(new URL("../src/lib/components/Approve.svelte", import.meta.url), "utf8");

function script(source, globals, expose) {
  const body = source.match(/<script lang="ts">([\s\S]*?)<\/script>/)[1]
    .replace(/^\s*import .*;$/gm, "");
  const js = ts.transpile(body, { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None });
  return new Function(...Object.keys(globals), `${js}\nreturn { ${expose} };`)(...Object.values(globals));
}

const a = { request_id: "A", action: "read", pin_digits: 4 };
const b = { request_id: "B", action: "write", pin_digits: 6 };
const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};

function mount(request, invoke, callbacks = {}) {
  let destroy;
  const component = script(approve, {
    $props: () => ({ request, ...callbacks }),
    $state: (value) => value,
    $derived: (value) => value,
    onDestroy: (callback) => { destroy = callback; },
    setTimeout: () => {},
    invoke,
    getInvokeError: (error) => error,
    formatInvokeError: (error) => error.message,
  }, "goToPin, setPinValue, submitPin, deny, get stage() { return stage; }, get pin() { return pinValue; }");
  return { ...component, state: component, destroy: () => destroy() };
}

test("a replacement request remounts at confirmation with an empty PIN", () => {
  assert.match(page, /\{#key JSON\.stringify\(pendingRequest\)\}[\s\S]*?<Approve/);
  const first = mount(a, () => {});
  first.goToPin();
  first.setPinValue("12");
  assert.equal(first.state.stage, "pin");
  assert.equal(first.state.pin, "12");
  first.destroy();
  const second = mount(b, () => {});
  assert.equal(second.state.stage, "confirm");
  assert.equal(second.state.pin, "");
});

test("approval and denial remain bound to their request and ignore completion after replacement", async () => {
  for (const operation of ["submitPin", "deny"]) {
    for (const fails of [false, true]) {
      const pending = deferred();
      const calls = [];
      const results = [];
      const first = mount(a, (...args) => { calls.push(args); return pending.promise; }, {
        onapproved: (...args) => results.push(args),
        ondenied: (...args) => results.push(args),
        onfailed: (...args) => results.push(args),
        onlocked: (...args) => results.push(args),
      });
      first.goToPin();
      const completion = first[operation]("1234");
      assert.equal(operation === "deny" ? calls[0][1].requestId : calls[0][1].payload.request_id, "A");
      first.destroy();
      mount(b, () => {});
      if (fails) pending.reject({ code: "app.session_expired", message: "expired" });
      else pending.resolve();
      await completion;
      assert.deepEqual(results, []);
    }
  }
});

test("failure reconciliation cannot overwrite a replacement request", async () => {
  const pending = deferred();
  const state = script(page, {
    $state: (value) => value,
    onMount: () => {},
    invoke: () => pending.promise,
  }, "onFailed, onApproved, onDenied, get pending() { return pendingRequest; }, get screen() { return screen; }, replace(request) { pendingRequest = request; screen = 'approve'; }");
  state.replace(a);
  const completion = state.onFailed(a, { reason: "A failed" });
  state.replace(b);
  pending.resolve(null);
  await completion;
  state.onApproved(a);
  state.onDenied(a);
  assert.equal(state.pending, b);
  assert.equal(state.screen, "approve");
});
