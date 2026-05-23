import type { Metadata } from "next";
import { Analytics } from "@vercel/analytics/next";
import { Plus_Jakarta_Sans, Fraunces, Source_Serif_4, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";
import { SiteFooter } from "@/components/SiteFooter";
import { SiteNav } from "@/components/SiteNav";
import { ThemeScript } from "@/components/ThemeScript";

const sans = Plus_Jakarta_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-sans",
  display: "swap",
});

const display = Fraunces({
  subsets: ["latin"],
  weight: "variable",
  variable: "--font-display",
  display: "swap",
  axes: ["opsz"],
});

const wordmark = Source_Serif_4({
  subsets: ["latin"],
  weight: ["600", "700"],
  variable: "--font-wordmark",
  display: "swap",
});

const mono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  metadataBase: new URL("https://raxis.io"),
  title: {
    default: "RAXIS: Runtime Attestation eXchange for Intelligent Systems",
    template: "%s · Raxis",
  },
  description:
    "RAXIS, the Runtime Attestation eXchange for Intelligent Systems, is a governed runtime for autonomous AI agents: user-signed authority, host-side enforcement, credential mediation, isolated execution, and tamper-evident audit for every privileged action.",
  openGraph: {
    title: "RAXIS: Runtime Attestation eXchange for Intelligent Systems",
    description:
      "Let agents work without giving them the keys. Users authorize the boundary, the kernel enforces it, and every decision lands in a tamper-evident audit chain.",
    type: "website",
    url: "/",
    siteName: "Raxis",
  },
  twitter: {
    card: "summary_large_image",
    title: "RAXIS: Runtime Attestation eXchange for Intelligent Systems",
    description:
      "Let agents work without giving them the keys. Users authorize the boundary, the kernel enforces it, and every decision lands in a tamper-evident audit chain.",
  },
  robots: { index: true, follow: true },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${sans.variable} ${display.variable} ${wordmark.variable} ${mono.variable}`}
    >
      <head>
        <ThemeScript />
      </head>
      <body suppressHydrationWarning className="min-h-dvh flex flex-col">
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded focus:bg-accent focus:px-3 focus:py-2 focus:text-white"
        >
          Skip to content
        </a>
        <SiteNav />
        <main id="main" className="flex-1">
          {children}
        </main>
        <SiteFooter />
        <Analytics />
      </body>
    </html>
  );
}
