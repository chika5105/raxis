import type { Metadata } from "next";
import "./globals.css";
import { SiteFooter } from "@/components/SiteFooter";
import { SiteNav } from "@/components/SiteNav";
import { ThemeScript } from "@/components/ThemeScript";

export const metadata: Metadata = {
  metadataBase: new URL("https://raxis.dev"),
  title: {
    default: "RAXIS — AI agents: authorized actions only, fully audited",
    template: "%s · RAXIS",
  },
  description:
    "RAXIS is the structural enforcement layer between AI intelligence and authority. A paradigm of 12 invariants that extends Lampson's 1974 protection model to autonomous agents — proven in a reference implementation for autonomous software engineering.",
  openGraph: {
    title: "RAXIS — AI agents: authorized actions only, fully audited",
    description:
      "12 paradigm invariants. Cryptographic admission on every action. Tamper-evident audit on every decision. The OS kernel for AI agents.",
    type: "website",
    url: "/",
    siteName: "RAXIS",
  },
  twitter: {
    card: "summary_large_image",
    title: "RAXIS — AI agents: authorized actions only, fully audited",
    description:
      "12 paradigm invariants. Cryptographic admission on every action. Tamper-evident audit on every decision.",
  },
  robots: { index: true, follow: true },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
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
