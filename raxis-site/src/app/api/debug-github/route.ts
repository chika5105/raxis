import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET() {
  const token = process.env.RAXIS_GITHUB_TOKEN ?? "";
  const repo = process.env.RAXIS_GITHUB_REPO ?? "";
  const force = process.env.RAXIS_FORCE_GITHUB ?? "";
  const prefix = process.env.RAXIS_GITHUB_PREFIX ?? "";
  const isDev = process.env.NODE_ENV;

  let treeStatus = 0;
  let error = "";
  try {
    const res = await fetch(
      `https://api.github.com/repos/${repo}/git/trees/main?recursive=1`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github.v3+json",
        },
        cache: "no-store",
      }
    );
    treeStatus = res.status;
  } catch (e) {
    error = String(e);
  }

  return NextResponse.json({
    token_length: token.length,
    token_prefix: token.slice(0, 20),
    repo,
    force,
    prefix,
    node_env: isDev,
    tree_api_status: treeStatus,
    error,
  });
}
