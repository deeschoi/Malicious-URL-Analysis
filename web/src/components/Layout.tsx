import { NavLink } from "react-router-dom";
import type { ReactNode } from "react";

const TABS = [
  { to: "/", label: "Scanner", end: true },
  { to: "/history", label: "History", end: false },
  { to: "/stats", label: "Stats", end: false },
  { to: "/findings", label: "Research findings", end: false },
] as const;

function SphinxMark() {
  return (
    <svg
      className="brand-mark"
      viewBox="0 0 40 40"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <defs>
        <linearGradient
          id="brand-gold"
          x1="4"
          y1="2"
          x2="36"
          y2="38"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="#f0d078" />
          <stop offset="1" stopColor="#c17a28" />
        </linearGradient>
      </defs>
      <rect width="40" height="40" rx="11" fill="url(#brand-gold)" />
      <path
        fill="#160e06"
        d="M11 9.2h10.2c1.3 0 2.1.9 2.1 2.1v4.1l8.6 2.5c2.1.6 3.3 2.5 3.1 4.6 2.5-1.4 3.1-6 .2-7.2-.2 2 .3 4.4-.8 5.6v5.6H8.6v-2.2H6.2v2.2H4.8v-3.3l3.4-1.5v-5.4L5.1 13.8c-.7-.4-.6-1.5.2-1.8L11 10.8V9.2z"
      />
      <circle cx="13.6" cy="13.1" r="0.95" fill="#f0d078" />
    </svg>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  return (
    <>
      <header className="masthead">
        <div className="wrap">
          <div className="brand">
            <SphinxMark />
            <div>
              <h1>Sphinx</h1>
              <p className="brand-kicker">URL Phishing Guardian</p>
              <p>
                Sphinx is a live phishing scanner. Paste a URL and it fetches the
                page, scores the risk with a trained classifier, and shows which
                signals decided the verdict.
              </p>
            </div>
          </div>
          {/* Plain navigation, not a tablist. role="tablist" without
              aria-selected/aria-controls told a screen reader these were tabs
              and then gave it none of the state a tab is supposed to carry. */}
          <nav className="tabs" aria-label="Sections">
            {TABS.map((tab) => (
              <NavLink
                key={tab.to}
                to={tab.to}
                end={tab.end}
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
          The scanner is trained on the PhiUSIIL Phishing URL dataset (Prasad
          &amp; Chandra, 2023): 48 features from the URL string and the fetched
          HTML, evaluated on a hold-out split grouped by hostname so no host
          appears in both training and test. Held-out accuracy is measured on
          that dataset's frozen columns; the live figures on each scan are the
          same model re-extracting features over the network, and they are the
          ones that describe a real scan.
        </p>
        <p>
          The <strong>Research findings</strong> tab is separate coursework on
          the older UCI Phishing Websites dataset (Mohammad, Thabtah &amp;
          McCluskey, 2012). Nothing there is used to score a URL.
        </p>
      </footer>
    </>
  );
}
