import { createBrowserRouter } from "react-router-dom";

import { AppShell } from "@/components/AppShell";
import { AccessMapPage } from "@/pages/AccessMap";
import { InventoryPage } from "@/pages/Inventory";
import { RiskPage } from "@/pages/Risk";
import { SearchPage } from "@/pages/Search";
import { TopologyPage } from "@/pages/Topology";
import { UploadPage } from "@/pages/Upload";

export const router = createBrowserRouter([
  {
    element: <AppShell />,
    children: [
      { path: "/", element: <UploadPage /> },
      { path: "/c/:configId/topology", element: <TopologyPage /> },
      { path: "/c/:configId/access", element: <AccessMapPage /> },
      { path: "/c/:configId/search", element: <SearchPage /> },
      { path: "/c/:configId/inventory", element: <InventoryPage /> },
      { path: "/c/:configId/risk", element: <RiskPage /> },
    ],
  },
]);
