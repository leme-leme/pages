"use client";

import { useEffect } from "react";

// Lightweight inline implementation of web-vitals collection so we don't
// pull in the full `web-vitals` npm package for ~3 metrics. The Performance
// APIs used here are all in the platform.
//
// Reports LCP, INP, CLS, FCP, TTFB to /api/_metrics/web-vitals via sendBeacon.
// Honors DNT/Sec-GPC at the browser layer too — no request is sent if either
// is set.

type VitalName = "LCP" | "INP" | "CLS" | "FCP" | "TTFB";

const isPrivacyOptOut = () =>
  typeof navigator !== "undefined" &&
  // @ts-expect-error: doNotTrack is non-standard but widely supported
  (navigator.doNotTrack === "1" || (window as any).doNotTrack === "1");

const send = (name: VitalName, value: number, navigationType?: string) => {
  if (isPrivacyOptOut()) return;
  if (typeof navigator === "undefined") return;

  const payload = JSON.stringify({
    name,
    value,
    id: `${name}-${Math.random().toString(36).slice(2, 10)}`,
    navigationType,
    page: typeof location !== "undefined" ? location.pathname : undefined,
  });

  try {
    if (navigator.sendBeacon) {
      navigator.sendBeacon("/api/_metrics/web-vitals", payload);
    } else {
      void fetch("/api/_metrics/web-vitals", {
        method: "POST",
        body: payload,
        keepalive: true,
        headers: { "Content-Type": "application/json" },
      });
    }
  } catch {
    // ignore — analytics must never break the app
  }
};

const observeLargestContentfulPaint = () => {
  try {
    const observer = new PerformanceObserver((list) => {
      const entries = list.getEntries();
      const last = entries[entries.length - 1] as PerformanceEntry & { startTime: number };
      if (last) send("LCP", last.startTime);
    });
    observer.observe({ type: "largest-contentful-paint", buffered: true });
  } catch {}
};

const observeFirstContentfulPaint = () => {
  try {
    const observer = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (entry.name === "first-contentful-paint") {
          send("FCP", entry.startTime);
        }
      }
    });
    observer.observe({ type: "paint", buffered: true });
  } catch {}
};

const observeCLS = () => {
  let cls = 0;
  let reported = false;
  try {
    const observer = new PerformanceObserver((list) => {
      for (const entry of list.getEntries() as Array<PerformanceEntry & {
        value: number;
        hadRecentInput: boolean;
      }>) {
        if (!entry.hadRecentInput) cls += entry.value;
      }
    });
    observer.observe({ type: "layout-shift", buffered: true });

    const flush = () => {
      if (reported) return;
      reported = true;
      send("CLS", Math.round(cls * 10000) / 10000);
    };
    addEventListener("pagehide", flush, { once: true });
    addEventListener("visibilitychange", () => {
      if (document.visibilityState === "hidden") flush();
    });
  } catch {}
};

const observeINP = () => {
  let worst = 0;
  let reported = false;
  try {
    const observer = new PerformanceObserver((list) => {
      for (const entry of list.getEntries() as PerformanceEventTiming[]) {
        const interactionLatency = entry.duration;
        if (interactionLatency > worst) worst = interactionLatency;
      }
    });
    // event timing is the closest proxy for INP available without the polyfill
    observer.observe({ type: "event", buffered: true, durationThreshold: 16 } as PerformanceObserverInit);

    const flush = () => {
      if (reported || worst <= 0) return;
      reported = true;
      send("INP", worst);
    };
    addEventListener("pagehide", flush, { once: true });
    addEventListener("visibilitychange", () => {
      if (document.visibilityState === "hidden") flush();
    });
  } catch {}
};

const observeTTFB = () => {
  try {
    const nav = performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined;
    if (nav) send("TTFB", nav.responseStart, nav.type);
  } catch {}
};

export function WebVitalsReporter() {
  useEffect(() => {
    if (typeof window === "undefined") return;
    if (isPrivacyOptOut()) return;
    observeLargestContentfulPaint();
    observeFirstContentfulPaint();
    observeCLS();
    observeINP();
    observeTTFB();
  }, []);
  return null;
}
