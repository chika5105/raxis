import { NextResponse } from "next/server";
import { refreshGitHubDocsBundle } from "@/lib/docs";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function isAuthorized(request: Request): boolean {
  if (process.env.NODE_ENV !== "production") return true;
  const secret = process.env.CRON_SECRET;
  if (secret) {
    return request.headers.get("authorization") === `Bearer ${secret}`;
  }
  return (request.headers.get("user-agent") ?? "").includes("vercel-cron/1.0");
}

export async function GET(request: Request) {
  if (!isAuthorized(request)) {
    return NextResponse.json({ ok: false, error: "unauthorized" }, { status: 401 });
  }

  const bundle = await refreshGitHubDocsBundle();
  return NextResponse.json({
    ok: true,
    fetchedAt: bundle.fetchedAt,
    documents: bundle.docs.length,
  });
}
