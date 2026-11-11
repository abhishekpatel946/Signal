import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Signal — cybersecurity account queue",
  description:
    "Ranked companies whose public attack surface says they need cybersecurity help now.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        <nav className="topnav">
          <a className="brand" href="/">
            Signal<span>.</span> cyber queue
          </a>
          <div className="navlinks">
            <a href="/">Accounts</a>
            <a href="/method">How scoring works</a>
          </div>
        </nav>
        {children}
      </body>
    </html>
  );
}
