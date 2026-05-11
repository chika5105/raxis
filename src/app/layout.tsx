import type { Metadata } from "next";
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
    default: "Raxis: AI agents, authorized actions only, fully audited",
    template: "%s · Raxis",
  },
  description:
    "Raxis (Runtime Attestation eXchange for Intelligent Systems) is a structural enforcement layer between AI agents and the systems they act on. Twelve invariants extending Lampson's 1974 protection model, with a working reference implementation in autonomous software engineering.",
  openGraph: {
    title: "Raxis: AI agents, authorized actions only, fully audited",
    description:
      "Twelve invariants. Cryptographic admission on every action. Tamper-evident audit on every decision.",
    type: "website",
    url: "/",
    siteName: "Raxis",
  },
  twitter: {
    card: "summary_large_image",
    title: "Raxis: AI agents, authorized actions only, fully audited",
    description:
      "Twelve invariants. Cryptographic admission on every action. Tamper-evident audit on every decision.",
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
      <body className="min-h-dvh flex flex-col">
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
      </body>
    </html>
  );
}
