import "./index.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router";

import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { createQueryClient } from "@/lib/query-client";
import { FleetPage } from "@/pages/fleet";
import { ChecksPage } from "@/pages/checks";
import { HistoryPage } from "@/pages/history";
import { NetworkPage } from "@/pages/network";
import { NotFoundPage } from "@/pages/not-found";
import { PasskeysPage } from "@/pages/passkeys";
import { StacksPage } from "@/pages/stacks";
import { AppShell } from "@/shell/app-shell";
import { SessionGate } from "@/shell/session-gate";

const queryClient = createQueryClient();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider delayDuration={150}>
        <BrowserRouter>
          <SessionGate>
            {(identity, via) => (
              <Routes>
                <Route element={<AppShell identity={identity} via={via} />}>
                  <Route index element={<FleetPage />} />
                  <Route path="network" element={<NetworkPage />} />
                  <Route path="stacks" element={<StacksPage />} />
                  <Route path="checks" element={<ChecksPage />} />
                  <Route path="passkeys" element={<PasskeysPage />} />
                  <Route path="history" element={<HistoryPage />} />
                  <Route path="*" element={<NotFoundPage />} />
                </Route>
              </Routes>
            )}
          </SessionGate>
        </BrowserRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  </StrictMode>,
);
