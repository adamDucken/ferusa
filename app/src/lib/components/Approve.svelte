<script lang="ts">
  import { onDestroy } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { Check, X } from "lucide-svelte";
  import { formatInvokeError, getInvokeError } from "$lib/errors";
  import SecurityFrame from "./SecurityFrame.svelte";

  type RequestPayload = {
    request_id: string;
    pin_digits?: number;
    correlation_code?: number;
    entry_title?: string;
    action?: string;
  };

  type Stage = "confirm" | "pin";

  let {
    request,
    retryMessage = "",
    onapproved,
    ondenied,
    onfailed,
    onlocked,
  }: {
    request: RequestPayload | null;
    retryMessage?: string;
    onapproved?: (request: RequestPayload) => void;
    ondenied?: (request: RequestPayload) => void;
    onfailed?: (request: RequestPayload, payload: { reason: string }) => void;
    onlocked?: (request: RequestPayload) => void;
  } = $props();

  let stage = $state<Stage>("confirm");
  let loading = $state(false);
  let pinValue = $state("");
  let pinError = $state("");
  let confirmedRequest: RequestPayload | null = null;
  let disposed = false;
  onDestroy(() => { disposed = true; });

  let requiredLength = $derived(request?.pin_digits ?? 4);

  function setPinValue(value: string) {
    pinValue = value.replace(/\D/g, "");
    if (pinValue) pinError = "";

    if (pinValue.length === requiredLength && !loading) {
      submitPin(pinValue);
    }
  }

  function goToPin() {
    if (!request) return;
    confirmedRequest = { ...request };
    stage = "pin";
    pinValue = "";
    pinError = "";
    focusPinInput();
  }

  function focusPinInput() {
    setTimeout(() => {
      if (disposed) return;
      document.querySelector<HTMLInputElement>('[data-pin-input="approve"]')?.focus();
    }, 50);
  }

  async function submitPin(finalPin: string) {
    const submittedRequest = confirmedRequest;
    if (disposed || loading || !submittedRequest || finalPin.length !== requiredLength
      || JSON.stringify(submittedRequest) !== JSON.stringify(request)) return;
    loading = true;
    try {
      await invoke("approve_request", {
        payload: {
          request_id: submittedRequest.request_id,
          pin: finalPin,
        },
      });
      if (!disposed) onapproved?.(submittedRequest);
    } catch (e: any) {
      if (disposed) return;
      const err = getInvokeError(e);
      const msg = formatInvokeError(e);
      const isWrongPin = err.code === "app.pin.incorrect";
      const isLocked =
        err.code === "app.pin.cooldown" || err.code === "app.session_expired";

      if (isWrongPin) {
        pinError = msg;
        pinValue = "";
        focusPinInput();
      } else if (isLocked) {
        onlocked?.(submittedRequest);
      } else {
        onfailed?.(submittedRequest, { reason: `Approval failed: ${msg}` });
      }
    } finally {
      loading = false;
    }
  }

  async function deny() {
    if (disposed || loading || !request) return;
    const submittedRequest = { ...request };
    loading = true;
    try {
      await invoke("deny_request", {
        requestId: submittedRequest.request_id,
      });
      if (!disposed) ondenied?.(submittedRequest);
    } catch (e: any) {
      if (!disposed) onfailed?.(submittedRequest, { reason: `Deny failed: ${formatInvokeError(e)}` });
    } finally {
      loading = false;
    }
  }

  function actionLabel(action?: string): string {
    return (action ?? "").toUpperCase();
  }
</script>

<SecurityFrame codeGap="12px" pinGap="12px" pinSlotMaxWidth="56px">
        {#if retryMessage}
          <div class="error-box" role="alert">{retryMessage}</div>
        {/if}
        {#if stage === "confirm"}
          <div class="title">
            <h1>Authorization</h1>
            <p>
              Verify this request by matching the<br />correlation code below.
            </p>
          </div>

          <div class="code-block">
            <span class="code-label">CORRELATION CODE</span>
            <div class="code-value">{request?.correlation_code}</div>
          </div>

          {#if request?.entry_title}
            <div class="meta-row request-entry-row">
              <span class="meta-label">Entry</span>
              <span class="meta-value request-entry-title" title={request.entry_title}
                >{request.entry_title}</span
              >
            </div>
          {/if}

          <div class="meta-row">
            <span class="meta-label">Action</span>
            <span class="meta-value action-badge"
              >{actionLabel(request?.action)}</span
            >
          </div>

          <div class="btn-stack">
            <button
              class="btn btn-approve"
              onclick={goToPin}
              disabled={loading}
            >
              {#if loading}
                <span class="spinner-inline"></span>
              {:else}
                <Check size={18} />
              {/if}
              Approve
            </button>
            <button class="btn btn-deny" onclick={deny} disabled={loading}>
              {#if loading}
                <span class="spinner-inline spinner-deny"></span>
              {:else}
                <X size={18} />
              {/if}
              Deny Request
            </button>
          </div>
        {:else}
          <div class="title">
            <h1>Authorization</h1>
            <p>
              Enter your {requiredLength}-digit PIN to<br />confirm this action.
            </p>
          </div>

          <div class="code-block relative-container">
            <label class="code-label" for="approve-pin-input">ENTER SECURITY PIN</label>

            <input
              data-pin-input="approve"
              id="approve-pin-input"
              bind:value={() => pinValue, setPinValue}
              type="password"
              inputmode="numeric"
              maxlength={requiredLength}
              disabled={loading}
              autocomplete="off"
              aria-invalid={Boolean(pinError)}
              aria-describedby={pinError ? "approve-pin-status approve-pin-error" : "approve-pin-status"}
              class="hidden-pin-input"
            />

            <div class="pin-dots" aria-hidden="true">
              {#each Array(requiredLength) as _, i (i)}
                <div
                  class={[
                    "pin-slot",
                    {
                      filled: pinValue.length > i,
                      active: pinValue.length === i && !loading,
                    },
                  ]}
                >
                  {#if pinValue.length > i}
                    <div class="dot"></div>
                  {/if}
                </div>
              {/each}
            </div>
            <p id="approve-pin-status" class="visually-hidden" aria-live="polite">
              {pinValue.length} of {requiredLength} PIN digits entered.
            </p>
          </div>

          {#if pinError}
            <div id="approve-pin-error" class="error-box" role="alert">{pinError}</div>
          {/if}

          <div class="btn-stack">
            <button
              class="btn btn-approve"
              onclick={() => submitPin(pinValue)}
              disabled={loading || pinValue.length !== requiredLength}
            >
              {#if loading}
                <span class="spinner-inline"></span>
                Verifying…
              {:else}
                <Check size={18} />
                Confirm
              {/if}
            </button>
            <button
              class="btn btn-deny"
              onclick={() => {
                stage = "confirm";
                pinError = "";
              }}
              disabled={loading}
            >
              <X size={18} />
              Cancel
            </button>
          </div>
        {/if}
</SecurityFrame>

<style>
  :global(.security-frame .error-box) {
    background: #fff2ee;
    color: #8a2f16;
    border-color: #f0c4b6;
    border-radius: 18px;
    padding: 12px 14px;
    font-size: 13px;
  }

  :global(.security-frame .request-entry-row) {
    align-items: flex-start;
  }

  :global(.security-frame .request-entry-title) {
    flex: 1 1 auto;
    max-width: 100%;
    display: -webkit-box;
    overflow: hidden;
    overflow-wrap: anywhere;
    word-break: break-word;
    line-height: 1.35;
    -webkit-box-orient: vertical;
    -webkit-line-clamp: 2;
    line-clamp: 2;
  }
</style>
