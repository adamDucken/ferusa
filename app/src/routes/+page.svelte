<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";

  import Setup from "$lib/components/Setup.svelte";
  import Biometric from "$lib/components/Biometric.svelte";
  import Approve from "$lib/components/Approve.svelte";
  import Idle from "$lib/components/Idle.svelte";
  import Success from "$lib/components/Success.svelte";
  import Failed from "$lib/components/Failed.svelte";
  import Reset from "$lib/components/Reset.svelte";
  import { formatInvokeError } from "$lib/errors";

  type Screen =
    | "loading"
    | "setup"
    | "biometric"
    | "approve"
    | "idle"
    | "success"
    | "failed"
    | "replace";

  type RequestPayload = {
    request_id: string;
    correlation_code?: number;
    entry_title?: string;
    action?: string;
    pin_digits?: number;
  };

  let screen = $state<Screen>("loading");
  let pendingRequest = $state<RequestPayload | null>(null);
  let failReason = $state("");
  let queuedRequest = $state<RequestPayload | null>(null);
  let isUnlocked = $state(false);
  let loadingMessage = $state("Loading ferusa...");
  let retryMessage = $state("");
  let setupMode = $state<"initial" | "replacement">("initial");
  let hasPairing: boolean | null = null;
  let lifecycleRevision = 0;

  function clearSession() {
    lifecycleRevision += 1;
    isUnlocked = false;
    pendingRequest = null;
    queuedRequest = null;
    retryMessage = "";
    failReason = "";
    setupMode = "initial";
    // Keep initial enrollment mounted, including its current step and scanner.
    screen = hasPairing === false ? "setup" : hasPairing ? "biometric" : "loading";
  }

  async function refreshSetup() {
    const revision = ++lifecycleRevision;
    try {
      const paired = await invoke<boolean>("check_setup");
      if (revision !== lifecycleRevision) return;
      hasPairing = paired;
      if (!paired) {
        setupMode = "initial";
        screen = "setup";
      } else if (!isUnlocked) {
        screen = "biometric";
      }
    } catch (e) {
      if (revision !== lifecycleRevision) return;
      console.error("check_setup failed:", formatInvokeError(e), e);
      if (hasPairing !== true) screen = "setup";
    }
  }

  async function reconcilePendingRequest(): Promise<RequestPayload | null | undefined> {
    const previousRequest = pendingRequest;
    const revision = lifecycleRevision;
    try {
      const request = await invoke<RequestPayload | null>("pending_request");
      // An event or lifecycle transition may have superseded this query.
      if (revision !== lifecycleRevision || pendingRequest !== previousRequest) return undefined;
      if (request) {
        if (isUnlocked) {
          pendingRequest = request;
          screen = "approve";
        } else {
          queuedRequest = request;
        }
      } else if (screen === "approve") {
        pendingRequest = null;
        retryMessage = "";
        screen = isUnlocked ? "idle" : "biometric";
      }
      return request;
    } catch (e) {
      console.error("pending_request failed:", formatInvokeError(e), e);
      return undefined;
    }
  }

  async function syncForegroundState() {
    const foreground = document.visibilityState === "visible";
    if (!foreground) clearSession();
    const revision = ++lifecycleRevision;
    try {
      await invoke("set_app_foreground", { foreground });
    } catch (e) {
      console.error("foreground state update failed:", formatInvokeError(e), e);
    }
    if (revision === lifecycleRevision) await refreshSetup();
  }

  onMount(() => {
    let unlisten: (() => void) | undefined;
    let unlistenSessionExpired: (() => void) | undefined;
    let unlistenSetupChanged: (() => void) | undefined;
    let disposed = false;
    const slowTimer = window.setTimeout(() => {
      loadingMessage = "Opening encrypted vault...";
    }, 1500);
    const verySlowTimer = window.setTimeout(() => {
      loadingMessage = "Still opening encrypted vault. First launch after security upgrade can take longer.";
    }, 6000);
    const reconcileTimer = window.setInterval(() => {
      void reconcilePendingRequest();
    }, 2000);

    function handleAuthRequest(request: RequestPayload) {
      retryMessage = "";
      if (isUnlocked) {
        pendingRequest = request;
        screen = "approve";
      } else {
        queuedRequest = request;
      }
    }

    const registerListeners = async () => {
      try {
        const authUnlisten = await listen<RequestPayload>(
          "ferusa://auth-request",
          (event) => handleAuthRequest(event.payload),
        );
        if (disposed) {
          authUnlisten();
        } else {
          unlisten = authUnlisten;
        }
      } catch (e) {
        console.error("auth-request listener failed:", formatInvokeError(e), e);
      }

      try {
        const sessionExpiredUnlisten = await listen(
          "ferusa://session-expired",
          () => {
            clearSession();
            void refreshSetup();
          },
        );
        if (disposed) {
          sessionExpiredUnlisten();
        } else {
          unlistenSessionExpired = sessionExpiredUnlisten;
        }
      } catch (e) {
        console.error(
          "session-expired listener failed:",
          formatInvokeError(e),
          e,
        );
      }

      try {
        const setupChangedUnlisten = await listen("ferusa://setup-changed", () => {
          clearSession();
          void refreshSetup();
        });
        if (disposed) {
          setupChangedUnlisten();
        } else {
          unlistenSetupChanged = setupChangedUnlisten;
        }
      } catch (e) {
        console.error("setup-changed listener failed:", formatInvokeError(e), e);
      }

      try {
        await reconcilePendingRequest();
      } catch (e) {
        console.error("initial pending_request failed:", formatInvokeError(e), e);
      }
    };

    const init = async () => {
      try {
        await refreshSetup();
      } finally {
        window.clearTimeout(slowTimer);
        window.clearTimeout(verySlowTimer);
      }
    };

    void init();
    void registerListeners();
    void syncForegroundState();

    return () => {
      disposed = true;
      lifecycleRevision += 1;
      window.clearTimeout(slowTimer);
      window.clearTimeout(verySlowTimer);
      window.clearInterval(reconcileTimer);
      unlisten?.();
      unlistenSessionExpired?.();
      unlistenSetupChanged?.();
    };
  });

  function onSetupComplete() {
    lifecycleRevision += 1;
    hasPairing = true;
    setupMode = "initial";
    screen = "biometric";
  }

  function onUnlocked() {
    if (document.visibilityState !== "visible" || hasPairing !== true) return;
    lifecycleRevision += 1;
    isUnlocked = true;

    if (queuedRequest) {
      pendingRequest = queuedRequest;
      queuedRequest = null;
      screen = "approve";
    } else {
      screen = "idle";
    }
  }

  function onLocked() {
    clearSession();
    void refreshSetup();
  }

  function isCurrentRequest(request: RequestPayload) {
    return screen === "approve" && JSON.stringify(pendingRequest) === JSON.stringify(request);
  }

  function onApprovalLocked(request: RequestPayload) {
    if (isCurrentRequest(request)) onLocked();
  }

  function onApproved(request: RequestPayload) {
    if (!isCurrentRequest(request)) return;
    screen = "success";
  }

  function onDenied(request: RequestPayload) {
    if (!isCurrentRequest(request)) return;
    failReason = "";
    screen = "failed";
  }

  async function onFailed(submittedRequest: RequestPayload, payload?: { reason: string }) {
    if (!isCurrentRequest(submittedRequest)) return;
    const reason = payload?.reason ?? "Something went wrong. Please try again.";
    let request: RequestPayload | null;
    try {
      request = await invoke<RequestPayload | null>("pending_request");
    } catch {
      if (isCurrentRequest(submittedRequest)) {
        retryMessage = `${reason} Checking the pending request…`;
      }
      return;
    }
    if (!isCurrentRequest(submittedRequest)) return;
    pendingRequest = request;
    if (request) {
      retryMessage = JSON.stringify(request) === JSON.stringify(submittedRequest) ? reason : "";
      screen = "approve";
    } else if (request === null) {
      failReason = reason;
      screen = "failed";
    }
  }

  function onResultDone() {
    pendingRequest = null;
    failReason = "";
    screen = "idle";
  }

  function onReplace() {
    lifecycleRevision += 1;
    screen = "replace";
  }

  function onReplacementAuthorized() {
    lifecycleRevision += 1;
    setupMode = "replacement";
    pendingRequest = null;
    queuedRequest = null;
    screen = "setup";
  }

  async function onReplacementCancel() {
    const revision = ++lifecycleRevision;
    try {
      await invoke("cancel_pairing_replacement");
    } catch (e) {
      console.error("cancel_pairing_replacement failed:", formatInvokeError(e), e);
    }
    if (revision !== lifecycleRevision) return;
    setupMode = "initial";
    screen = isUnlocked ? "idle" : "biometric";
  }
</script>

<main>
  {#if screen === "loading"}
    <div class="center"><p>{loadingMessage}</p></div>
  {:else if screen === "setup"}
    <Setup
      mode={setupMode}
      oncomplete={onSetupComplete}
      oncancel={setupMode === "replacement" ? onReplacementCancel : undefined}
    />
  {:else if screen === "biometric"}
    <Biometric onunlocked={onUnlocked} />
  {:else if screen === "replace"}
    <Reset onauthorized={onReplacementAuthorized} oncancel={onReplacementCancel} />
  {:else if screen === "approve"}
    {#if pendingRequest}
      {#key JSON.stringify(pendingRequest)}
      <Approve
        request={pendingRequest}
        {retryMessage}
        onapproved={onApproved}
        ondenied={onDenied}
        onfailed={onFailed}
        onlocked={onApprovalLocked}
      />
      {/key}
    {/if}
  {:else if screen === "success"}
    <Success request={pendingRequest} ondone={onResultDone} />
  {:else if screen === "failed"}
    <Failed
      request={pendingRequest}
      reason={failReason}
      ondone={onResultDone}
    />
  {:else if screen === "idle"}
    <Idle onlocked={onLocked} onreplace={onReplace} />
  {/if}
</main>

<svelte:document onvisibilitychange={syncForegroundState} />

<style>
  :global(body) {
    margin: 0;
    background: #0f0f0f;
    color: #f0f0f0;
    font-family: system-ui, sans-serif;
  }
  :global(.sveltekit-body) {
    display: contents;
  }
  .center {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100vh;
  }
</style>
