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

  async function reconcilePendingRequest(): Promise<RequestPayload | null | undefined> {
    try {
      const request = await invoke<RequestPayload | null>("pending_request");
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
    try {
      await invoke("set_app_foreground", { foreground });
    } catch (e) {
      console.error("foreground state update failed:", formatInvokeError(e), e);
    }
    if (!foreground) {
      isUnlocked = false;
      pendingRequest = null;
      queuedRequest = null;
      retryMessage = "";
      screen = "biometric";
    }
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
            isUnlocked = false;
            pendingRequest = null;
            queuedRequest = null;
            failReason = "";
            screen = "biometric";
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
          isUnlocked = false;
          pendingRequest = null;
          queuedRequest = null;
          failReason = "";
          screen = "biometric";
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
        const isSetup: boolean = await invoke("check_setup");
        setupMode = "initial";
        screen = isSetup ? "biometric" : "setup";
      } catch (e) {
        console.error("check_setup failed:", formatInvokeError(e), e);
        screen = "setup";
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
      window.clearTimeout(slowTimer);
      window.clearTimeout(verySlowTimer);
      window.clearInterval(reconcileTimer);
      unlisten?.();
      unlistenSessionExpired?.();
      unlistenSetupChanged?.();
    };
  });

  function onSetupComplete() {
    setupMode = "initial";
    screen = "biometric";
  }

  function onUnlocked() {
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
    isUnlocked = false;
    screen = "biometric";
  }

  function onApproved() {
    screen = "success";
  }

  function onDenied() {
    failReason = "";
    screen = "failed";
  }

  async function onFailed(payload?: { reason: string }) {
    const reason = payload?.reason ?? "Something went wrong. Please try again.";
    const request = await reconcilePendingRequest();
    if (request) {
      retryMessage = reason;
      screen = "approve";
    } else if (request === null) {
      failReason = reason;
      screen = "failed";
    } else {
      retryMessage = `${reason} Checking the pending request…`;
      screen = "approve";
    }
  }

  function onResultDone() {
    pendingRequest = null;
    failReason = "";
    screen = "idle";
  }

  function onReplace() {
    screen = "replace";
  }

  function onReplacementAuthorized() {
    setupMode = "replacement";
    pendingRequest = null;
    queuedRequest = null;
    screen = "setup";
  }

  async function onReplacementCancel() {
    try {
      await invoke("cancel_pairing_replacement");
    } catch (e) {
      console.error("cancel_pairing_replacement failed:", formatInvokeError(e), e);
    }
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
      <Approve
        request={pendingRequest}
        {retryMessage}
        onapproved={onApproved}
        ondenied={onDenied}
        onfailed={onFailed}
        onlocked={onLocked}
      />
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
