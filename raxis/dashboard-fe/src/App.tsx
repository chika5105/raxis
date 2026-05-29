import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

import { ApiError } from "@/api/client";
import { RequireAuth } from "@/components/RequireAuth";
import { Shell } from "@/components/Shell";
import { AuditPage } from "@/pages/Audit";
import { EscalationsPage } from "@/pages/Escalations";
import { GatesPage } from "@/pages/Gates";
import { GitPage } from "@/pages/Git";
import { GlossaryPage } from "@/pages/Glossary";
import { HealthPage } from "@/pages/Health";
import { InboxPage } from "@/pages/Inbox";
import { InitiativeDagPage } from "@/pages/InitiativeDag";
import { InitiativeDetailPage } from "@/pages/InitiativeDetail";
import { InitiativesPage } from "@/pages/Initiatives";
import { LoginPage } from "@/pages/Login";
import { NotificationsPage } from "@/pages/Notifications";
import { OverviewPage } from "@/pages/Overview";
import { PlanBuilderPage } from "@/pages/PlanBuilder";
import { PolicyBuilderPage, PolicyPage } from "@/pages/Policy";
import { SessionDetailPage } from "@/pages/SessionDetail";
import { SessionsPage } from "@/pages/Sessions";
import { SystemCredentialsPage } from "@/pages/SystemCredentials";
import { TaskDetailPage } from "@/pages/TaskDetail";
import { WorktreeDetailPage } from "@/pages/WorktreeDetail";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      gcTime: 5 * 60_000,
      retry: (failureCount, error) => {
        // Never retry 4xx — they are deterministic. Backoff
        // a couple of times for transient 5xx / network errors.
        if (error instanceof ApiError && error.status >= 400 && error.status < 500) {
          return false;
        }
        return failureCount < 2;
      },
      refetchOnWindowFocus: false,
    },
  },
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter
        future={{
          // Opt-in to react-router v7 behaviour now so the v6 console
          // warnings (logged as `console.error`) stop polluting every
          // page load. These two flags are no-op upgrades — they only
          // change internals, not our route definitions.
          v7_startTransition: true,
          v7_relativeSplatPath: true,
        }}
      >
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="*"
            element={
              <RequireAuth>
                <Shell>
                  <Routes>
                    <Route path="/" element={<OverviewPage />} />
                    <Route path="/glossary" element={<GlossaryPage />} />
                    <Route path="/health" element={<HealthPage />} />
                    <Route path="/inbox" element={<InboxPage />} />
                    <Route path="/notifications" element={<NotificationsPage />} />
                    <Route path="/initiatives" element={<InitiativesPage />} />
                    <Route path="/plan-builder" element={<PlanBuilderPage />} />
                    <Route path="/tool-builder" element={<Navigate to="/plan-builder" replace />} />
                    <Route path="/initiatives/:id" element={<InitiativeDetailPage />} />
                    <Route path="/initiatives/:id/dag" element={<InitiativeDagPage />} />
                    <Route path="/tasks/:id" element={<TaskDetailPage />} />
                    <Route path="/sessions" element={<SessionsPage />} />
                    <Route
                      path="/sessions/recent"
                      element={<Navigate to="/sessions?scope=past" replace />}
                    />
                    <Route path="/sessions/:id" element={<SessionDetailPage />} />
                    <Route path="/escalations" element={<EscalationsPage />} />
                    <Route path="/audit" element={<AuditPage />} />
                    <Route path="/gates" element={<GatesPage />} />
                    {/* iter69 — the standalone /witnesses page
                        was merged into /gates (per-gate rollup
                        + cross-task verdict timeline now live
                        on a single surface). Keep a redirect so
                        bookmarks + grafana panels survive. */}
                    <Route
                      path="/witnesses"
                      element={<Navigate to="/gates" replace />}
                    />
                    <Route path="/git" element={<GitPage />} />
                    <Route path="/git/:name" element={<WorktreeDetailPage />} />
                    <Route path="/policy" element={<PolicyPage />} />
                    <Route path="/policy-builder" element={<PolicyBuilderPage />} />
                    <Route
                      path="/system/credentials"
                      element={<SystemCredentialsPage />}
                    />
                    <Route path="*" element={<Navigate to="/" replace />} />
                  </Routes>
                </Shell>
              </RequireAuth>
            }
          />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
