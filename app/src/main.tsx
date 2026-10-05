import "./index.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router";

import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ChecksPage } from "@/pages/checks";
import { CloudflarePage } from "@/pages/cloudflare";
import { FleetPage } from "@/pages/fleet";
import { IncidentDetailPage } from "@/pages/incident-detail";
import { HistoryPage } from "@/pages/history";
import { IncidentsPage } from "@/pages/incidents";
import { createQueryClient } from "@/lib/query-client";
import { NodeDetailPage } from "@/pages/node-detail";
import { NotFoundPage } from "@/pages/not-found";
import { ServicesPage } from "@/pages/services";
import { DevicesPage } from "./pages/devices";
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
                  <Route path="nodes/:id" element={<NodeDetailPage />} />
                  <Route path="services" element={<ServicesPage />} />
                  <Route path="devices" element={<DevicesPage />} />
                  <Route path="checks" element={<ChecksPage />} />
                  <Route path="incidents" element={<IncidentsPage />} />
                  <Route path="history" element={<HistoryPage />} />
                  <Route
                    path="settings/cloudflare"
                    element={<CloudflarePage />}
                  />
                  <Route
                    path="incidents/:id"
                    element={<IncidentDetailPage />}
                  />
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
