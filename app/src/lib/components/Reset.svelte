<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { AlertTriangle, Check } from "lucide-svelte";
  import { formatInvokeError, getInvokeError } from "$lib/errors";
  import SecurityFrame from "./SecurityFrame.svelte";

  let {
    onauthorized,
    oncancel,
  }: {
    onauthorized?: () => void;
    oncancel?: () => void;
  } = $props();

  type Step = "pin4" | "pin6" | "biometric" | "disclaimer";

  let step = $state<Step>("pin4");
  let loading = $state(false);
  let error = $state("");
  let pin4 = $state("");
  let pin6 = $state("");
  let lockedOut = $state(false);

  const stepNumber: Record<Step, number> = {
    pin4: 1,
    pin6: 2,
    biometric: 3,
    disclaimer: 4,
  };
  const totalSteps = 4;

  let canAuthorizeReplacement = $derived(
    /^\d{4}$/.test(pin4) && /^\d{6}$/.test(pin6) && !loading && !lockedOut,
  );

  function onPin4Submit() {
    if (!/^\d{4}$/.test(pin4) || loading || lockedOut) {
      error = "4-digit PIN required (digits only).";
      return;
    }

    error = "";
    step = "pin6";
    focusPinInput("pin6");
  }

  function focusPinInput(target: "pin4" | "pin6") {
    setTimeout(() => {
      document
        .querySelector<HTMLInputElement>(`[data-pin-input="${target}"]`)
        ?.focus();
    }, 50);
  }

  function onPin6Submit() {
    if (!/^\d{6}$/.test(pin6) || loading || lockedOut) {
      error = "6-digit PIN required (digits only).";
      return;
    }

    error = "";
    authorizeReplacement();
  }

  async function authorizeReplacement() {
    if (!canAuthorizeReplacement) return;

    loading = true;
    step = "biometric";
    error = "";
    try {
      await invoke("authorize_pairing_replacement", {
        payload: {
          pin4,
          pin6,
        },
      });
      loading = false;
      step = "disclaimer";
    } catch (e: any) {
      const err = getInvokeError(e);
      lockedOut =
        err.code === "app.pin.too_many_attempts" ||
        err.code === "app.pin.cooldown";
      error = formatInvokeError(e);
      pin4 = "";
      pin6 = "";
      loading = false;
      step = lockedOut ? "biometric" : "pin4";
      if (!lockedOut) {
        focusPinInput("pin4");
      }
    }
  }

  function continueToReplacement() {
    if (loading || lockedOut) return;
    onauthorized?.();
  }

  function setPin4(value: string) {
    pin4 = value.replace(/\D/g, "").slice(0, 4);

    if (pin4.length === 4 && step === "pin4" && !loading && !lockedOut) {
      onPin4Submit();
    }
  }

  function setPin6(value: string) {
    pin6 = value.replace(/\D/g, "").slice(0, 6);

    if (pin6.length === 6 && step === "pin6" && !loading && !lockedOut) {
      onPin6Submit();
    }
  }

  function cancel() {
    oncancel?.();
  }
</script>

<SecurityFrame pinGap="8px">
        <div class="progress-header">
          <span class="progress-label">Replacement Authorization</span>
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

        {#if step === "pin4" || step === "pin6"}
          {@const requiredLength = step === "pin6" ? 6 : 4}
          {@const currentPin = step === "pin6" ? pin6 : pin4}

          <div class="title">
            <h1>{step === "pin6" ? "Write PIN" : "Read PIN"}</h1>
            {#if step === "pin6"}
              <p>
                Enter your current 6-digit PIN to authorize pairing replacement.
                Biometric confirmation follows.
              </p>
            {:else}
              <p>
                Enter your current 4-digit PIN. Your existing pairing remains
                active until replacement safely completes.
              </p>
            {/if}
          </div>

          <div class="code-block relative-container">
            <label class="code-label" for="replacement-pin-input">ENTER SECURITY PIN</label>

            {#if step === "pin4"}
              <input
                data-pin-input="pin4"
                id="replacement-pin-input"
                bind:value={() => pin4, setPin4}
                type="password"
                inputmode="numeric"
                maxlength={4}
                disabled={loading || lockedOut}
                autocomplete="off"
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "replacement-pin-status replacement-pin-error" : "replacement-pin-status"}
                class="hidden-pin-input"
              />
            {:else}
              <input
                data-pin-input="pin6"
                id="replacement-pin-input"
                bind:value={() => pin6, setPin6}
                type="password"
                inputmode="numeric"
                maxlength={6}
                disabled={loading || lockedOut}
                autocomplete="off"
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "replacement-pin-status replacement-pin-error" : "replacement-pin-status"}
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
                      active: currentPin.length === i && !loading && !lockedOut,
                    },
                  ]}
                >
                  {#if currentPin.length > i}
                    <div class="dot"></div>
                  {/if}
                </div>
              {/each}
            </div>
            <p id="replacement-pin-status" class="visually-hidden" aria-live="polite">
              {currentPin.length} of {requiredLength} PIN digits entered.
            </p>
          </div>

          {#if error}
            <div id="replacement-pin-error" class="error-box" role="alert">{error}</div>
          {/if}

          <div class="btn-stack">
            <button
              class="btn btn-approve"
              onclick={() => {
                if (step === "pin4") onPin4Submit();
                else onPin6Submit();
              }}
              disabled={loading || lockedOut || currentPin.length !== requiredLength}
            >
              <Check size={18} />
              {step === "pin6" ? "Authorize Replacement" : "Continue"}
            </button>
            <button class="btn btn-cancel" onclick={cancel} disabled={loading}>
              Cancel
            </button>
          </div>
        {:else if step === "biometric"}
          <div class="title">
            <h1>{lockedOut ? "Replacement Blocked" : "Confirm Replacement"}</h1>
            <p>
              {lockedOut
                ? "Too many incorrect PIN attempts. Pairing replacement is temporarily unavailable."
                : "Complete biometric confirmation before reviewing the safe replacement steps."}
            </p>
          </div>

          <div class="code-block biometric-block">
            {#if loading}
              <span class="spinner-large"></span>
            {:else}
              <div class="icon-wrap">
                <AlertTriangle size={40} strokeWidth={1.5} />
              </div>
            {/if}
            <span class="code-label">
              {loading ? "WAITING FOR BIOMETRICS" : "REPLACE PAIRING"}
            </span>
          </div>

          {#if error}
            <div class="error-box">{error}</div>
          {/if}

          <div class="btn-stack">
            <button class="btn btn-cancel" onclick={cancel} disabled={loading}>
              Cancel
            </button>
          </div>
        {:else}
          <div class="icon-wrap">
            <AlertTriangle size={40} strokeWidth={1.5} />
          </div>

          <div class="title">
            <h1>Replace Pairing Safely</h1>
            <p>
              The current phone share stays active until your desktop vault has
              been re-encrypted and both devices durably activate the replacement.
            </p>
          </div>

          <div class="info-block">
            <p class="info-item">Keep this app open and the current pairing available</p>
            <p class="info-item">Run <code>ferusa pair</code> on the desktop first</p>
            <p class="info-item">Scan the new QR code on the next screen</p>
            <p class="info-item">Biometric confirmation has passed</p>
            <p class="info-item">Both PINs were entered correctly</p>
            <p class="info-item">
              A failure before commit leaves the current pairing and vault usable
            </p>
          </div>

          {#if error}
            <div class="error-box">{error}</div>
          {/if}

          <div class="btn-stack">
            <button
              class="btn btn-approve"
              onclick={continueToReplacement}
              disabled={loading || lockedOut}
            >
              {#if loading}
                <span class="spinner-inline"></span>
                Preparing…
              {:else}
                Continue to Pairing
              {/if}
            </button>
            <button class="btn btn-cancel" onclick={cancel} disabled={loading}>
              Cancel
            </button>
          </div>
        {/if}
</SecurityFrame>

<style>
  .biometric-block {
    min-height: 120px;
    justify-content: center;
  }

  .icon-wrap {
    width: 80px;
    height: 80px;
    border-radius: 50%;
    background: #fff7ed;
    color: #c2410c;
    box-shadow: 0 0 0 6px #ffedd5;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .info-block {
    width: 100%;
    box-sizing: border-box;
    background: #faf9f4;
    border-radius: 20px;
    padding: 18px 20px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .info-item {
    margin: 0;
    font-size: 13px;
    color: #56423c;
    line-height: 1.45;
    padding-left: 18px;
    position: relative;
  }

  .info-item::before {
    content: ".";
    position: absolute;
    left: 6px;
    color: #994121;
    font-weight: 700;
  }

  @media (max-width: 380px) {
    :global(.security-frame .pin-dots) {
      gap: 7px;
    }
  }
</style>
