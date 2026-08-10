import { NavLink, Outlet, useParams } from "react-router-dom";

const TABS = [
  { to: "topology", label: "Topology" },
  { to: "access", label: "Access map" },
  { to: "search", label: "Search" },
  { to: "inventory", label: "Inventory" },
];

export function AppShell() {
  const { configId } = useParams<{ configId: string }>();

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b bg-card">
        <div className="mx-auto flex max-w-[1400px] items-center gap-8 px-6 py-3">
          <NavLink to="/" className="font-semibold tracking-tight">
            pfSense Network Map
          </NavLink>
          {configId && (
            <nav className="flex gap-1 text-sm">
              {TABS.map((tab) => (
                <NavLink
                  key={tab.to}
                  to={`/c/${configId}/${tab.to}`}
                  className={({ isActive }) =>
                    [
                      "cursor-pointer rounded-md px-3 py-1.5 transition-colors duration-150",
                      isActive
                        ? "bg-primary text-primary-foreground"
                        : "text-muted-foreground hover:bg-muted",
                    ].join(" ")
                  }
                >
                  {tab.label}
                </NavLink>
              ))}
            </nav>
          )}
        </div>
      </header>
      <main className="mx-auto max-w-[1400px] px-6 py-6">
        <Outlet />
      </main>
    </div>
  );
}
