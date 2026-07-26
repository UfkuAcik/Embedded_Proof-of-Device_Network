import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: {
    default: "EPDN Network",
    template: "%s · EPDN",
  },
  description:
    "Monitor provisioned embedded miners, explore PoPED blocks, and manage a local-first testnet wallet.",
  applicationName: "EPDN Network",
  manifest: "/manifest.webmanifest",
  appleWebApp: {
    capable: true,
    statusBarStyle: "black-translucent",
    title: "EPDN",
  },
  formatDetection: { telephone: false },
  icons: {
    icon: [
      { url: "/icon-32.png", type: "image/png", sizes: "32x32" },
      { url: "/icon-192.png", type: "image/png", sizes: "192x192" },
    ],
    shortcut: "/icon-32.png",
    apple: "/icon-192.png",
  },
  openGraph: {
    type: "website",
    title: "EPDN Network",
    description:
      "Embedded proof-of-device testnet dashboard, wallet, and explorer.",
    images: [
      {
        url: "/og.png",
        width: 1200,
        height: 630,
        alt: "EPDN Network embedded proof-of-device topology",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "EPDN Network",
    description:
      "Embedded proof-of-device testnet dashboard, wallet, and explorer.",
    images: ["/og.png"],
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  viewportFit: "cover",
  colorScheme: "dark light",
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#f3f1e9" },
    { media: "(prefers-color-scheme: dark)", color: "#07100e" },
  ],
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${geistSans.variable} ${geistMono.variable}`}>
        <a className="skip-link" href="#main-content">
          Skip to content
        </a>
        {children}
      </body>
    </html>
  );
}
