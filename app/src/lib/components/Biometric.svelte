<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import logo from "$lib/assets/ferusa.png";
  import { Unlock } from "lucide-svelte";
  import { formatInvokeError } from "$lib/errors";
  import SecurityFrame from "./SecurityFrame.svelte";

  let { onunlocked }: { onunlocked?: () => void } = $props();

  let error = $state("");
  let loading = $state(false);

  async function unlock() {
    loading = true;
    error = "";
    try {
      await invoke("biometric_unlock");
      onunlocked?.();
    } catch (e: any) {
      error = formatInvokeError(e);
    } finally {
      loading = false;
    }
  }
</script>

<SecurityFrame variant="home">
            <div class="title">
              <h1>Locked</h1>
              <p>Use biometrics to unlock the app</p>
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

            <button class="btn" onclick={unlock} disabled={loading}>
              {#if loading}
                <span class="spinner-inline"></span>
                Authenticating…
              {:else}
                Unlock
                <Unlock />
              {/if}
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
</style>
