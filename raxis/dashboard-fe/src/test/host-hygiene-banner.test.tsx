/* HostHygieneBanner — INV-HOST-HYGIENE-01.
 *
 * The banner subscribes to the operator-notification stream and
 * surfaces an amber strip when the live-e2e harness (or any
 * future kernel-side preflight) emits
 * `OperatorAttentionRequired { attention_kind:
 * "HostHygieneDiskPressure" }`. These tests pin:
 *   * the JSON-payload parsing path (string `details` containing
 *     a `HostPreflightError::DiskPressure` body),
 *   * the rendered title / volume / remediation copy,
 *   * the dismiss persistence (sessionStorage),
 *   * the no-render-when-empty contract.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { dashboardApi } from "@/api/client";
import {
  extractHygieneEvents,
  HostHygieneBanner,
} from "@/components/banners/HostHygieneBanner";
import type { NotificationView } from "@/types/api";

function diskPressureNotification(
  override: Partial<NotificationView> = {},
): NotificationView {
  // Mirrors the wire shape the kernel writes for
  // `OperatorAttentionRequired { attention_kind, details }` —
  // payload is the variant body. The `details` field is a
  // JSON-encoded `HostPreflightError::DiskPressure`.
  return {
    notification_id: "n-1",
    event_kind: "OperatorAttentionRequired",
    initiative_id: null,
    task_id: null,
    session_id: null,
    summary: "Host disk pressure detected",
    payload: {
      attention_kind: "HostHygieneDiskPressure",
      details: JSON.stringify({
        pressure_kind: "DiskPressure",
        threshold_pct: 90,
        observed_volumes: [
          {
            mount: "/System/Volumes/Data",
            used_pct: 92,
            free_human: "64.0GiB",
          },
          {
            mount: "/private/tmp",
            used_pct: 78,
            free_human: "199.0GiB",
          },
        ],
        remediation_cmd: "cargo xtask hygiene",
        docs_url: "raxis/guides/operator/18-host-hygiene.md",
      }),
    },
    read: false,
    source_event_id: "src-1",
    created_at: 1_700_000_000,
    priority: "High",
    ...override,
  };
}

function renderBanner(rows: NotificationView[]) {
  vi.spyOn(dashboardApi.notifications, "list").mockResolvedValue(rows);
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchInterval: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <HostHygieneBanner />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  if (typeof window !== "undefined" && window.sessionStorage) {
    window.sessionStorage.clear();
  }
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<HostHygieneBanner>", () => {
  it("renders nothing when there are no host-hygiene notifications", async () => {
    const { container } = renderBanner([]);
    // Give react-query one tick to resolve the empty fetch.
    await waitFor(() =>
      expect(dashboardApi.notifications.list).toHaveBeenCalled(),
    );
    expect(container.querySelector("[data-testid='host-hygiene-banner']")).toBeNull();
  });

  it("surfaces the offending volume + remediation on a DiskPressure event", async () => {
    renderBanner([diskPressureNotification()]);

    const banner = await screen.findByTestId("host-hygiene-banner");
    expect(banner).toHaveTextContent("Host disk pressure");
    expect(banner).toHaveTextContent("/System/Volumes/Data");
    expect(banner).toHaveTextContent("92%");
    expect(banner).toHaveTextContent("free 64.0GiB");
    // Under-threshold volume must NOT appear in the title row —
    // it is mute context, not a banner-title concern.
    expect(banner).not.toHaveTextContent("/private/tmp");
    expect(banner).toHaveTextContent("cargo xtask hygiene");
  });

  it("dismiss button hides the banner and persists to sessionStorage", async () => {
    renderBanner([diskPressureNotification()]);
    const banner = await screen.findByTestId("host-hygiene-banner");
    expect(banner).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: "Dismiss host disk pressure banner" }),
    );
    await waitFor(() =>
      expect(screen.queryByTestId("host-hygiene-banner")).toBeNull(),
    );

    // sessionStorage carries the dismissal so a fresh page mount
    // does NOT re-surface the same event the operator already
    // dismissed in this session. Pinning the storage key here
    // also catches a future rename of `DISMISS_STORAGE_KEY`
    // before it silently breaks dismiss persistence.
    const stored = window.sessionStorage.getItem(
      "raxis.host_hygiene_banner.dismissed_event_ids",
    );
    expect(stored).not.toBeNull();
    const ids = JSON.parse(stored ?? "[]") as string[];
    expect(ids).toContain("n-1");
  });

  it("Copy remediation invokes the clipboard with `cargo xtask hygiene`", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    renderBanner([diskPressureNotification()]);
    await screen.findByTestId("host-hygiene-banner");
    fireEvent.click(
      screen.getByRole("button", { name: "Copy remediation command" }),
    );
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    expect(writeText).toHaveBeenCalledWith("cargo xtask hygiene");
  });

  it("ignores OperatorAttentionRequired events with a different attention_kind", async () => {
    const unrelated: NotificationView = {
      notification_id: "n-2",
      event_kind: "OperatorAttentionRequired",
      initiative_id: null,
      task_id: null,
      session_id: null,
      summary: "Disk full halt entered",
      payload: {
        attention_kind: "DiskFull",
        details: "free_mb=128, floor=512, behavior=halt_admit",
      },
      read: false,
      source_event_id: "src-2",
      created_at: 1_700_000_001,
      priority: "High",
    };
    const { container } = renderBanner([unrelated]);
    await waitFor(() =>
      expect(dashboardApi.notifications.list).toHaveBeenCalled(),
    );
    expect(container.querySelector("[data-testid='host-hygiene-banner']")).toBeNull();
  });
});

describe("extractHygieneEvents", () => {
  it("parses a JSON-string `details` payload into a typed event", () => {
    const events = extractHygieneEvents([diskPressureNotification()]);
    expect(events).toHaveLength(1);
    expect(events[0].attention_kind).toBe("HostHygieneDiskPressure");
    expect(events[0].details.pressure_kind).toBe("DiskPressure");
    expect(events[0].details.threshold_pct).toBe(90);
    expect(events[0].details.observed_volumes?.[0].mount).toBe(
      "/System/Volumes/Data",
    );
    expect(events[0].details.remediation_cmd).toBe("cargo xtask hygiene");
  });

  it("tolerates an already-parsed `details` object (forward-compat)", () => {
    const row = diskPressureNotification();
    (row.payload as { details?: unknown }).details = {
      pressure_kind: "DiskPressure",
      threshold_pct: 90,
      observed_volumes: [
        { mount: "/srv/data", used_pct: 95, free_human: "12.0GiB" },
      ],
      remediation_cmd: "cargo xtask hygiene",
    };
    const events = extractHygieneEvents([row]);
    expect(events).toHaveLength(1);
    expect(events[0].details.observed_volumes?.[0].mount).toBe("/srv/data");
  });

  it("skips rows whose `details` is malformed JSON", () => {
    const row = diskPressureNotification();
    (row.payload as { details?: unknown }).details = "{not valid json";
    const events = extractHygieneEvents([row]);
    expect(events).toHaveLength(0);
  });
});
