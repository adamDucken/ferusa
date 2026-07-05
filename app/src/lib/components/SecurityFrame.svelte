<script lang="ts">
  import type { Snippet } from "svelte";

  let {
    children,
    variant = "form",
    codeGap = "16px",
    pinGap = "10px",
    pinSlotMaxWidth = "52px",
  }: {
    children: Snippet;
    variant?: "form" | "home" | "status";
    codeGap?: string;
    pinGap?: string;
    pinSlotMaxWidth?: string;
  } = $props();
</script>

<div
  class={["security-frame", `security-frame-${variant}`]}
  style:--security-code-gap={codeGap}
  style:--security-pin-gap={pinGap}
  style:--security-pin-slot-max-width={pinSlotMaxWidth}
>
  <div class="security-main">
    <div class="security-center">
      <div class="security-content">
        <div class="security-card">
          <div class="security-card-inner">
            {@render children()}
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<style>
  .security-frame {
    background: #b1ada1;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    box-sizing: border-box;
  }

  .security-frame-status {
    animation: security-fade-in 0.3s ease;
  }

  .security-main {
    flex: 1;
    position: relative;
  }

  .security-center {
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    width: 100%;
  }

  .security-content {
    position: relative;
    width: 100%;
    max-width: 448px;
    padding: 24px;
    box-sizing: border-box;
  }

  .security-frame-home .security-content {
    max-width: 800px;
  }

  .security-card {
    background: #f5f4ef;
    border-radius: 48px;
    max-width: 448px;
    margin: 0 auto;
    padding: 4px;
  }

  .security-card-inner {
    background: white;
    border-radius: 44px;
    padding: 32px 28px;
    display: flex;
    flex-direction: column;
    gap: 24px;
    align-items: center;
  }

  .security-frame-home .security-card-inner {
    padding: 32px;
    gap: 28px;
  }

  .security-frame-status .security-card-inner {
    padding: 36px 28px 28px;
    gap: 20px;
  }

  .security-frame :global(.title) {
    text-align: center;
    width: 100%;
  }

  .security-frame :global(.title h1) {
    font-size: var(--security-title-size, 26px);
    font-weight: 800;
    margin: 0;
    color: #1b1c19;
    letter-spacing: 0;
  }

  .security-frame-home :global(.title h1) {
    --security-title-size: 30px;
  }

  .security-frame :global(.title p) {
    font-size: 14px;
    color: #56423c;
    margin: 8px 0 0;
    line-height: 1.5;
  }

  .security-frame :global(.title strong) {
    color: #994121;
  }

  .security-frame-status :global(.title strong) {
    color: #1b1c19;
  }

  .security-frame :global(.progress-header) {
    width: 100%;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .security-frame :global(.progress-label) {
    font-size: 12px;
    font-weight: 600;
    color: rgba(86, 66, 60, 0.6);
    letter-spacing: 0.3px;
  }

  .security-frame :global(.progress-step) {
    font-size: 12px;
    font-weight: 700;
    color: #994121;
  }

  .security-frame :global(.progress-track) {
    width: 100%;
    display: flex;
    gap: 6px;
  }

  .security-frame :global(.progress-segment) {
    flex: 1;
    height: 5px;
    border-radius: 999px;
    background: #e3e3de;
    transition: background 0.3s ease;
  }

  .security-frame :global(.progress-segment.active) {
    background: #994121;
  }

  .security-frame :global(.code-block) {
    width: 100%;
    box-sizing: border-box;
    background: #faf9f4;
    border-radius: 24px;
    padding: 20px 24px;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--security-code-gap);
  }

  .security-frame :global(.relative-container) {
    position: relative;
  }

  .security-frame :global(.code-label),
  .security-frame :global(.field-label) {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1.2px;
    color: rgba(86, 66, 60, 0.7);
    text-transform: uppercase;
  }

  .security-frame :global(.code-value) {
    font-size: 52px;
    font-weight: 800;
    color: #994121;
    letter-spacing: 0.12em;
    line-height: 1;
  }

  .security-frame :global(.hidden-pin-input) {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    opacity: 0;
    z-index: 10;
    cursor: pointer;
    font-size: 24px;
    color: transparent;
    background: transparent;
    caret-color: transparent;
    border: none;
    outline: none;
  }

  .security-frame :global(.hidden-pin-input:disabled) {
    cursor: not-allowed;
  }

  .security-frame :global(.visually-hidden) {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }

  .security-frame :global(.pin-dots) {
    display: flex;
    gap: var(--security-pin-gap);
    justify-content: center;
    align-items: center;
    width: 100%;
  }

  .security-frame :global(.pin-slot) {
    position: relative;
    flex: 1 1 0;
    max-width: var(--security-pin-slot-max-width);
    min-width: 0;
    aspect-ratio: 13 / 12;
    background: #e3e3de;
    border-radius: 9999px;
    display: flex;
    align-items: center;
    justify-content: center;
    transition:
      background 0.15s,
      box-shadow 0.15s;
  }

  .security-frame :global(.pin-slot.filled) {
    background: #d4cfc8;
  }

  .security-frame :global(.pin-slot.active) {
    box-shadow: 0 0 0 2px #994121;
    background: #e3e3de;
  }

  .security-frame :global(.dot) {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: #994121;
    pointer-events: none;
    transition: transform 0.1s;
  }

  .security-frame :global(.meta-row) {
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 0 4px;
    box-sizing: border-box;
  }

  .security-frame :global(.meta-label) {
    flex: 0 0 auto;
    font-size: 13px;
    color: rgba(86, 66, 60, 0.6);
    font-weight: 500;
  }

  .security-frame :global(.meta-value) {
    min-width: 0;
    overflow-wrap: anywhere;
    text-align: right;
    font-size: 13px;
    color: #1b1c19;
    font-weight: 600;
  }

  .security-frame :global(.action-badge) {
    flex: 0 0 auto;
    background: #f0ede6;
    color: #994121;
    border-radius: 999px;
    padding: 3px 12px;
    font-size: 11px;
    letter-spacing: 0.8px;
  }

  .security-frame :global(.error-box) {
    width: 100%;
    box-sizing: border-box;
    background: #fee2e2;
    color: #991b1b;
    border: 1px solid #f87171;
    border-radius: 12px;
    padding: 12px 16px;
    font-size: 14px;
    line-height: 1.35;
    text-align: center;
  }

  .security-frame :global(.btn-stack) {
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .security-frame :global(.btn) {
    width: 100%;
    padding: 16px;
    border-radius: 999px;
    border: none;
    color: white;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    background: linear-gradient(167deg, #c15f3c 0%, #994121 100%);
    box-shadow: 0 20px 40px -10px rgba(193, 95, 60, 0.4);
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    transition:
      transform 0.1s,
      opacity 0.2s;
  }

  .security-frame-home :global(.btn) {
    font-size: 18px;
  }

  .security-frame :global(.btn:active:not(:disabled)) {
    transform: scale(0.98);
  }

  .security-frame :global(.btn:disabled) {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .security-frame-home :global(.btn:disabled) {
    opacity: 0.7;
  }

  .security-frame :global(.btn-approve) {
    color: white;
  }

  .security-frame :global(.btn-deny),
  .security-frame :global(.btn-cancel) {
    color: #994121;
    background: #f5f4ef;
    border: 1.5px solid #e0d9d0;
    box-shadow: none;
  }

  .security-frame :global(.btn-deny:hover:not(:disabled)),
  .security-frame :global(.btn-cancel:hover:not(:disabled)) {
    background: #ede9e1;
  }

  .security-frame :global(.btn-danger) {
    color: white;
    background: #7e2b12;
    box-shadow: none;
  }

  .security-frame :global(.btn.secondary) {
    background: linear-gradient(167deg, #55433c 0%, #302420 100%);
    box-shadow: 0 20px 40px -10px rgba(48, 36, 32, 0.25);
  }

  .security-frame :global(.spinner-inline) {
    display: inline-block;
    width: var(--security-spinner-size, 16px);
    height: var(--security-spinner-size, 16px);
    border: 2px solid rgba(255, 255, 255, 0.3);
    border-top-color: #ffffff;
    border-radius: 50%;
    animation: security-spin 0.7s linear infinite;
  }

  .security-frame-home :global(.spinner-inline) {
    --security-spinner-size: 18px;
  }

  .security-frame :global(.spinner-deny) {
    border-color: rgba(153, 65, 33, 0.2);
    border-top-color: #994121;
  }

  .security-frame :global(.spinner-large) {
    display: inline-block;
    width: 40px;
    height: 40px;
    border: 3px solid #e3e3de;
    border-top-color: #994121;
    border-radius: 50%;
    animation: security-spin 0.8s linear infinite;
  }

  .security-frame :global(code) {
    background: #f0ede6;
    color: #994121;
    border-radius: 6px;
    padding: 0.1em 0.45em;
    font-size: 0.88em;
    font-family: monospace;
  }

  @media (max-width: 380px) {
    .security-content {
      padding: 16px;
    }

    .security-card-inner {
      padding: 28px 20px;
    }

    .security-frame :global(.code-block) {
      padding: 18px 16px;
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .security-frame :global(*),
    .security-frame :global(*::before),
    .security-frame :global(*::after) {
      animation-duration: 0.01ms !important;
      animation-iteration-count: 1 !important;
      scroll-behavior: auto !important;
      transition-duration: 0.01ms !important;
    }
  }

  @keyframes security-spin {
    to {
      transform: rotate(360deg);
    }
  }

  @keyframes security-fade-in {
    from {
      opacity: 0;
      transform: translateY(8px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }
</style>
