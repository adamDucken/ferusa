<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import {
    Format,
    checkPermissions,
    requestPermissions,
    scan,
  } from "@tauri-apps/plugin-barcode-scanner";
  import { Check } from "lucide-svelte";
  import { formatInvokeError } from "$lib/errors";
  import SecurityFrame from "./SecurityFrame.svelte";

  let {
    oncomplete,
    oncancel,
    mode = "initial",
  }: {
    oncomplete: () => void;
    oncancel?: () => void;
    mode?: "initial" | "replacement";
  } = $props();

  type Step =
    | "node-id"
    | "pin4"
    | "pin4-confirm"
    | "pin6"
    | "pin6-confirm"
    | "verify-code"
    | "pairing";

  let step = $state<Step>("node-id");
  let cliNodeId = $state("");
  let pin4 = $state("");
  let pin4Confirm = $state("");
  let pin6 = $state("");
  let pin6Confirm = $state("");
  let pairingCode = $state("");
  let error = $state("");
  let loading = $state(false);

  let scanning = $state(false);
  let scanError = $state("");

  // Step number for progress bar (pairing is still step 3 visually)
  const stepNumber: Record<Step, number> = {
    "node-id": 1,
    pin4: 2,
    "pin4-confirm": 2,
    pin6: 3,
    "pin6-confirm": 3,
    "verify-code": 4,
    pairing: 4,
  };
  const totalSteps = 4;

  onMount(async () => {
    try {
      const perm = await checkPermissions();
      if (
        String(perm) === "prompt" ||
        String(perm) === "prompt-with-rationale"
      ) {
        await requestPermissions();
      }
    } catch (_) {}
  });

  // ── QR scanning ──────────────────────────────────────────────────────────────

  async function startScan() {
    scanError = "";
    scanning = true;
    try {
      let perm = await checkPermissions();
      if (String(perm) !== "granted") {
        const req = await requestPermissions();
        if (String(req) !== "granted") {
          scanError =
            "Camera permission denied. Go to Settings → Apps → ferusa → Permissions.";
          return;
        }
      }
      const result = await scan({ formats: [Format.QRCode], windowed: false });
      const content = result.content?.trim() ?? "";
      if (/^[0-9a-fA-F]{64}$/.test(content)) {
        cliNodeId = content;
        error = "";
        scanError = "";
      } else {
        scanError =
          "Scanned content doesn't look like a node ID. Try again or enter manually.";
      }
    } catch (e: any) {
      const msg = String(e);
      if (!msg.toLowerCase().includes("cancel")) {
        scanError = `Scan failed: ${msg}`;
      }
    } finally {
      scanning = false;
    }
  }

  // ── Step navigation ───────────────────────────────────────────────────────────

  function onNodeIdSubmit() {
    const trimmed = cliNodeId.trim();
    if (!/^[0-9a-fA-F]{64}$/.test(trimmed)) {
      error = "Node ID must be 64 hex characters.";
      return;
    }
    cliNodeId = trimmed;
    error = "";
    step = "pin4";
    focusPinInput("pin4");
  }

  function onPin4Submit() {
    if (!/^\d{4}$/.test(pin4)) {
      error = "4-digit PIN required (digits only).";
      return;
    }
    if (isTrivialPin(pin4)) {
      error = "Choose a PIN that is not common, repeated, or sequential.";
      return;
    }
    error = "";
    step = "pin4-confirm";
    focusPinInput("pin4-confirm");
  }

  function onPin4ConfirmSubmit() {
    if (pin4Confirm !== pin4) {
      error = "PINs do not match.";
      pin4Confirm = "";
      return;
    }
    error = "";
    step = "pin6";
    focusPinInput("pin6");
  }

  function onPin6Submit() {
    if (!/^\d{6}$/.test(pin6)) {
      error = "6-digit PIN required (digits only).";
      return;
    }
    if (isTrivialPin(pin6)) {
      error = "Choose a PIN that is not common, repeated, or sequential.";
      return;
    }
    error = "";
    step = "pin6-confirm";
    focusPinInput("pin6-confirm");
  }

  function focusPinInput(target: Step) {
    setTimeout(() => {
      document
        .querySelector<HTMLInputElement>(`[data-pin-input="${target}"]`)
        ?.focus();
    }, 50);
  }

  function isTrivialPin(pin: string): boolean {
    const repeated = /^(\d)\1+$/.test(pin);
    const ascending = "0123456789".includes(pin);
    const descending = "9876543210".includes(pin);
    const common = ["1212", "1122", "2580", "121212", "112233", "258025"].includes(pin);
    return repeated || ascending || descending || common;
  }

  function onPin6ConfirmSubmit() {
    if (pin6Confirm !== pin6) {
      error = "PINs do not match.";
      pin6Confirm = "";
      return;
    }
    error = "";
    showPairingVerification();
  }

  async function showPairingVerification() {
    loading = true;
    try {
      pairingCode = await invoke<string>("setup_pairing_code");
      error = "";
      step = "verify-code";
    } catch (e: any) {
      error = formatInvokeError(e);
    } finally {
      loading = false;
    }
  }

  function onPairingCodeConfirmed() {
    finishSetup();
  }

  async function finishSetup() {
    loading = true;
    step = "pairing";
    try {
      await invoke("setup_complete", {
        payload: {
          pin4,
          pin6,
          cli_node_id_hex: cliNodeId,
        },
      });
      oncomplete();
    } catch (e: any) {
      error = formatInvokeError(e);
      step = "node-id";
      loading = false;
    }
  }

  function setPin4(value: string) {
    pin4 = value.replace(/\D/g, "");

    if (pin4.length === 4 && step === "pin4" && !loading) {
      onPin4Submit();
    }
  }

  function setPin4Confirm(value: string) {
    pin4Confirm = value.replace(/\D/g, "");

    if (pin4Confirm.length === 4 && step === "pin4-confirm" && !loading) {
      onPin4ConfirmSubmit();
    }
  }

  function setPin6(value: string) {
    pin6 = value.replace(/\D/g, "");

    if (pin6.length === 6 && step === "pin6" && !loading) {
      onPin6Submit();
    }
  }

  function setPin6Confirm(value: string) {
    pin6Confirm = value.replace(/\D/g, "");

    if (pin6Confirm.length === 6 && step === "pin6-confirm" && !loading) {
      onPin6ConfirmSubmit();
    }
  }
</script>

<SecurityFrame>
        <!-- ── Progress bar ─────────────────────────────────────────────────── -->
        <div class="progress-header">
          <span class="progress-label">
            {mode === "replacement" ? "Replacement Progress" : "Setup Progress"}
          </span>
          <span class="progress-step"
            >Step {stepNumber[step]} of {totalSteps}</span
          >
        </div>
        <div class="progress-track">
          {#each Array(totalSteps) as _, i (i)}
            <div
              class={[
                "progress-segment",
                { active: i + 1 <= stepNumber[step] },
              ]}
            ></div>
          {/each}
        </div>

        <!-- ── Node ID step ─────────────────────────────────────────────────── -->
        {#if step === "node-id"}
          <div class="title">
            <h1>{mode === "replacement" ? "Replace Pairing" : "Pair Device"}</h1>
            <p>
              Run <code>{mode === "replacement" ? "ferusa pair" : "ferusa init"}</code>
              on your desktop, then scan the QR code to establish a secure link.
              {#if mode === "replacement"}
                Do not clear the current phone or desktop pairing while this runs.
              {/if}
            </p>
          </div>

          <div class="code-block">
            <span class="code-label">SCAN QR CODE</span>

            <button
              class="btn btn-approve scan-btn"
              onclick={startScan}
              disabled={scanning}
            >
              {#if scanning}
                <span class="spinner-inline"></span>
                Opening camera…
              {:else}
                Scan QR Code
              {/if}
            </button>

            {#if scanError}
              <div class="error-box">{scanError}</div>
            {/if}
          </div>

          <div class="field-group">
            <span class="field-label">NODE ID</span>
            <textarea
              bind:value={cliNodeId}
              rows="2"
              spellcheck="false"
              autocomplete="off"
              placeholder="64-character hex node ID…"
              class="node-textarea"
            ></textarea>
          </div>

          {#if error}
            <div class="error-box">{error}</div>
          {/if}

          <div class="btn-stack">
            <button
              class="btn btn-approve"
              onclick={onNodeIdSubmit}
              disabled={!cliNodeId.trim()}
            >
              <Check size={18} />
              Continue
            </button>
            {#if mode === "replacement"}
              <button class="btn btn-cancel" onclick={oncancel} disabled={loading}>
                Cancel Replacement
              </button>
            {/if}
          </div>

          <!-- ── PIN steps ─────────────────────────────────────────────────────── -->
        {:else if step === "pin4" || step === "pin4-confirm" || step === "pin6" || step === "pin6-confirm"}
          {@const requiredLength =
            step === "pin6" || step === "pin6-confirm" ? 6 : 4}
          {@const currentPin =
            step === "pin4"
              ? pin4
              : step === "pin4-confirm"
                ? pin4Confirm
                : step === "pin6"
                  ? pin6
                  : pin6Confirm}

          <div class="title">
            {#if step === "pin4"}
              <h1>Read PIN</h1>
              <p>
                Set a 4-digit PIN.<br />Used to approve <strong>read</strong> requests.
              </p>
            {:else if step === "pin4-confirm"}
              <h1>Confirm PIN</h1>
              <p>Re-enter your 4-digit PIN to confirm.</p>
            {:else if step === "pin6"}
              <h1>Write PIN</h1>
              <p>
                Set a 6-digit PIN.<br />Used to approve
                <strong>create, update & delete</strong> requests.
              </p>
            {:else}
              <h1>Confirm PIN</h1>
              <p>Re-enter your 6-digit PIN to confirm.</p>
            {/if}
          </div>

          <div class="code-block relative-container">
            <label class="code-label" for="setup-pin-input">ENTER SECURITY PIN</label>

            <!-- Hidden input -->
            {#if step === "pin4"}
              <input
                data-pin-input="pin4"
                id="setup-pin-input"
                bind:value={() => pin4, setPin4}
                type="password"
                inputmode="numeric"
                maxlength={4}
                disabled={loading}
                autocomplete="off"
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "setup-pin-status setup-pin-error" : "setup-pin-status"}
                class="hidden-pin-input"
              />
            {:else if step === "pin4-confirm"}
              <input
                data-pin-input="pin4-confirm"
                id="setup-pin-input"
                bind:value={() => pin4Confirm, setPin4Confirm}
                type="password"
                inputmode="numeric"
                maxlength={4}
                disabled={loading}
                autocomplete="off"
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "setup-pin-status setup-pin-error" : "setup-pin-status"}
                class="hidden-pin-input"
              />
            {:else if step === "pin6"}
              <input
                data-pin-input="pin6"
                id="setup-pin-input"
                bind:value={() => pin6, setPin6}
                type="password"
                inputmode="numeric"
                maxlength={6}
                disabled={loading}
                autocomplete="off"
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "setup-pin-status setup-pin-error" : "setup-pin-status"}
                class="hidden-pin-input"
              />
            {:else}
              <input
                data-pin-input="pin6-confirm"
                id="setup-pin-input"
                bind:value={() => pin6Confirm, setPin6Confirm}
                type="password"
                inputmode="numeric"
                maxlength={6}
                disabled={loading}
                autocomplete="off"
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "setup-pin-status setup-pin-error" : "setup-pin-status"}
                class="hidden-pin-input"
              />
            {/if}

            <div class="pin-dots" aria-hidden="true">
              {#each Array(requiredLength) as _, i (i)}
                <div
                  class={[
                    "pin-slot",
                    {
                      filled: currentPin.length > i,
                      active: currentPin.length === i && !loading,
                    },
                  ]}
                >
                  {#if currentPin.length > i}
                    <div class="dot"></div>
                  {/if}
                </div>
              {/each}
            </div>
            <p id="setup-pin-status" class="visually-hidden" aria-live="polite">
              {currentPin.length} of {requiredLength} PIN digits entered.
            </p>
          </div>

          {#if error}
            <div id="setup-pin-error" class="error-box" role="alert">{error}</div>
          {/if}

          <div class="btn-stack">
            <button
              class="btn btn-approve"
              onclick={() => {
                if (step === "pin4") onPin4Submit();
                else if (step === "pin4-confirm") onPin4ConfirmSubmit();
                else if (step === "pin6") onPin6Submit();
                else onPin6ConfirmSubmit();
              }}
              disabled={loading || currentPin.length !== requiredLength}
            >
              {#if loading}
                <span class="spinner-inline"></span>
                Saving…
              {:else}
                <Check size={18} />
                Continue
              {/if}
            </button>
          </div>

          <!-- ── Pairing verification ───────────────────────────────────────────── -->
        {:else if step === "verify-code"}
          <div class="title">
            <h1>Verify Pairing</h1>
            <p>
              Confirm this code matches the one shown on your desktop before
              pairing.
            </p>
          </div>

          <div class="code-block">
            <span class="code-label">PAIRING CODE</span>
            <div class="code-value">{pairingCode}</div>
          </div>

          {#if error}
            <div class="error-box">{error}</div>
          {/if}

          <div class="btn-stack">
            <button
              class="btn btn-approve"
              onclick={onPairingCodeConfirmed}
              disabled={loading}
            >
              {#if loading}
                <span class="spinner-inline"></span>
                Pairing…
              {:else}
                <Check size={18} />
                Start Pairing
              {/if}
            </button>
          </div>

          <!-- ── Pairing spinner ───────────────────────────────────────────────── -->
        {:else if step === "pairing"}
          <div class="title">
            <h1>Pairing</h1>
            <p>Confirm this code on your desktop.</p>
          </div>

          <div class="code-block pairing-block">
            <span class="code-label">PAIRING CODE</span>
            <div class="code-value">{pairingCode}</div>
            <span class="spinner-large"></span>
            <span class="code-label">ESTABLISHING SECURE LINK</span>
          </div>

          {#if error}
            <div class="error-box">{error}</div>
          {/if}
        {/if}
</SecurityFrame>

<style>
  .scan-btn {
    width: auto;
    padding: 14px 32px;
    font-size: 15px;
  }

  .field-group {
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .field-label {
    padding: 0 2px;
  }

  .node-textarea {
    width: 100%;
    box-sizing: border-box;
    background: #faf9f4;
    border: 1.5px solid #e0d9d0;
    border-radius: 16px;
    color: #1b1c19;
    font-family: monospace;
    font-size: 12px;
    line-height: 1.6;
    padding: 14px 16px;
    resize: none;
    outline: none;
    transition: border-color 0.15s;
  }

  .node-textarea::placeholder {
    color: rgba(86, 66, 60, 0.4);
  }

  .node-textarea:focus {
    border-color: #994121;
  }

  .pairing-block {
    min-height: 120px;
    justify-content: center;
  }
</style>
