import type { MetadataRoute } from "next";
import { getAllDocs } from "@/lib/docs";

const BASE_URL = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.raxis.io";

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const now = new Date();
  const staticEntries: MetadataRoute.Sitemap = [
    "",
    "/paradigm",
    "/threat-model",
    "/reference",
    "/conformance",
    "/about",
    "/get-started",
    "/plan-builder",
    "/docs",
    "/docs/search",
  ].map((p) => ({
    url: `${BASE_URL}${p}`,
    lastModified: now,
    changeFrequency: "weekly",
    priority: p === "" ? 1.0 : 0.8,
  }));

  const docEntries: MetadataRoute.Sitemap = (await getAllDocs()).map((doc) => ({
    url: `${BASE_URL}/docs/${doc.slugPath}`,
    lastModified: now,
    changeFrequency: "weekly",
    priority: 0.5,
  }));

  return [...staticEntries, ...docEntries];
}
