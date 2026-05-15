import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getDocBySlug } from "@/lib/docs";
import { renderMarkdown } from "@/lib/markdown";
import { PageHeader } from "@/components/PageHeader";

export const revalidate = 3600;

export const metadata: Metadata = {
  title: "Investor Overview — Raxis",
  description:
    "RAXIS: the OS kernel for AI agents. Deterministic enforcement, cryptographic audit, and fail-closed architecture for the agentic economy.",
};

export default async function InvestorsPage() {
  const found = await getDocBySlug(["investors"]);
  if (!found) notFound();

  const { html } = await renderMarkdown(found.raw, found.meta.relativePath);

  return (
    <>
      <PageHeader
        eyebrow="Investors"
        title="RAXIS: The OS Kernel for AI Agents"
        lead="For accelerators, technical investors, and security-conscious enterprises evaluating the agentic infrastructure layer."
      />
      <div className="mx-auto max-w-4xl px-4 sm:px-6 py-12 sm:py-16">
        <div
          className="doc-prose"
          dangerouslySetInnerHTML={{ __html: html }}
        />

        <div className="mt-16 border-t border-[var(--rule)] pt-10 flex flex-wrap gap-4">
          <Link href="/paradigm" className="btn btn-primary">
            Read the paradigm
          </Link>
          <a
            href="mailto:chikajinanwa@raxis.io"
            className="text-base text-[var(--fg)] hover:text-accent underline underline-offset-4 decoration-[var(--rule)] hover:decoration-accent transition"
          >
            Contact Chika →
          </a>
          <a
            href="https://www.linkedin.com/in/chika-jinanwa/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-base text-[var(--muted)] hover:text-[var(--fg)] underline underline-offset-4 decoration-[var(--rule)] transition"
          >
            LinkedIn
          </a>
        </div>
      </div>
    </>
  );
}
