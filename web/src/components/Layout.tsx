import { NavLink } from "react-router-dom";
import type { ReactNode } from "react";

const TABS = [
  { to: "/", label: "Scanner", end: true },
  { to: "/history", label: "History", end: false },
  { to: "/stats", label: "Stats", end: false },
  { to: "/findings", label: "Research findings", end: false },
] as const;

export function Layout({ children }: { children: ReactNode }) {
  return (
    <>
      <header className="masthead">
        <div className="wrap">
          <div className="brand">
            <span className="brand-mark" />
            <div>
              <h1>Phishing URL Scanner</h1>
              <p>
                Gradient-boosted classifier over the UCI Phishing Websites feature set,
                with per-signal attribution.
              </p>
            </div>
          </div>
          <nav className="tabs" role="tablist">
            {TABS.map((tab) => (
              <NavLink
                key={tab.to}
                to={tab.to}
                end={tab.end}
                role="tab"
                className={({ isActive }) => (isActive ? "tab is-active" : "tab")}
              >
                {tab.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>
      <main className="wrap">
        <section className="view">{children}</section>
      </main>
      <footer className="wrap footer">
        <p>
          Trained on the UCI Phishing Websites dataset (Mohammad, Thabtah &amp; McCluskey,
          2012). Accuracy figures come from a grouped hold-out split in which no
          duplicate feature pattern is shared between training and test data.
        </p>
      </footer>
    </>
  );
}
