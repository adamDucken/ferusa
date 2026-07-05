<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import logo from "$lib/assets/ferusa.png";
  import { Lock } from "lucide-svelte";
  import { formatInvokeError } from "$lib/errors";
  import SecurityFrame from "./SecurityFrame.svelte";

  let {
    onlocked,
    onreplace,
  }: {
    onlocked?: () => void;
    onreplace?: () => void;
  } = $props();

  let error = $state("");
  let loading = $state(false);

  async function lock() {
    loading = true;
    error = "";
    try {
      await invoke("lock");
      // After locking, we usually want to tell the parent to show the biometric screen again
      onlocked?.();
    } catch (e: any) {
      error = formatInvokeError(e);
    } finally {
      loading = false;
    }
  }

  function replacePairing() {
    onreplace?.();
  }
</script>

<SecurityFrame variant="home">
            <div class="title">
              <h1>Unlocked</h1>
              <p>Waiting for requests...</p>
            </div>

            {#if error}
              <div class="error-box">
                {error}
              </div>
            {/if}

            <div class="biometric-card">
              <div class="biometric-inner">
                <div class="avatar">
                  <img src={logo} alt="ferusa" />
                </div>
              </div>
            </div>

            <button class="btn secondary" onclick={lock} disabled={loading}>
              {#if loading}
                <span class="spinner-inline"></span>
                Locking…
              {:else}
                Lock
                <Lock />
              {/if}
            </button>

            <button class="replacement-link" onclick={replacePairing} disabled={loading}>
              Replace paired desktop
            </button>
</SecurityFrame>

<style>
  .biometric-card {
    width: 100%;
    box-sizing: border-box;
    background: #faf9f4;
    border-radius: 48px;
    padding: 36px 32px;
  }

  .biometric-inner {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 20px;
  }

  .avatar {
    width: 160px;
    height: 160px;
    border-radius: 50%;
    overflow: hidden;
    box-shadow: 0 20px 48px -8px rgba(59, 9, 0, 0.18);
  }

  .avatar img {
    width: 100%;
    height: 100%;
    object-fit: cover;
    transform: scale(1.7);
  }

  .replacement-link {
    background: none;
    border: none;
    padding: 0;
    font-size: 11px;
    color: rgba(86, 66, 60, 0.38);
    cursor: pointer;
    letter-spacing: 0.2px;
    text-decoration: underline;
    text-underline-offset: 3px;
    text-decoration-color: rgba(86, 66, 60, 0.2);
    transition:
      color 0.2s,
      text-decoration-color 0.2s;
    margin-top: -14px;
  }

  .replacement-link:hover:not(:disabled) {
    color: rgba(86, 66, 60, 0.6);
    text-decoration-color: rgba(86, 66, 60, 0.4);
  }

  .replacement-link:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
</style>
