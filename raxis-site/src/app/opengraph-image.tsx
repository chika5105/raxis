import { ImageResponse } from "next/og";

export const alt = "RAXIS — AI agents: authorized actions only, fully audited";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          background: "#0b0e14",
          color: "#ececee",
          padding: "72px 80px",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          fontFamily: "ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
          <div
            style={{
              width: 56,
              height: 56,
              borderRadius: 12,
              background: "#0BCCE7",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontFamily: "ui-monospace, SFMono-Regular, Menlo",
              fontWeight: 800,
              fontSize: 36,
              color: "#0b0e14",
              letterSpacing: "-0.06em",
            }}
          >
            r
          </div>
          <div
            style={{
              fontFamily: "ui-monospace, SFMono-Regular, Menlo",
              fontSize: 32,
              fontWeight: 700,
              letterSpacing: "-0.02em",
              color: "#ececee",
            }}
          >
            raxis
          </div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
          <div
            style={{
              fontFamily: "ui-monospace, SFMono-Regular, Menlo",
              fontSize: 18,
              textTransform: "uppercase",
              letterSpacing: "0.18em",
              color: "#0BCCE7",
            }}
          >
            Runtime Attestation eXchange for Intelligent Systems
          </div>
          <div
            style={{
              fontSize: 78,
              lineHeight: 1.04,
              fontWeight: 600,
              letterSpacing: "-0.03em",
              maxWidth: 1040,
              display: "flex",
              flexDirection: "column",
              gap: 4,
            }}
          >
            <span>AI agents:</span>
            <span>
              <span style={{ color: "#ececee" }}>authorized actions only,</span>
            </span>
            <span style={{ color: "#0BCCE7" }}>fully audited.</span>
          </div>
        </div>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            fontSize: 18,
            color: "#8a93a3",
            borderTop: "1px solid rgba(255,255,255,0.10)",
            paddingTop: 22,
          }}
        >
          <div style={{ display: "flex", gap: 28 }}>
            <span>12 paradigm invariants</span>
            <span>·</span>
            <span>Cryptographic admission</span>
            <span>·</span>
            <span>Tamper-evident audit</span>
          </div>
          <div style={{ color: "#ececee" }}>raxis.dev</div>
        </div>
      </div>
    ),
    size,
  );
}
