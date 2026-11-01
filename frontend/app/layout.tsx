import type { Metadata, Viewport } from "next";
import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import "./globals.css";
export const metadata: Metadata = { title: "PatchProof — Find the flaw. Prove the fix.", description: "Upload C/C++ source for static analysis, review findings, and verify repair proposals.", icons: { icon: "/icon.svg" } };
export const viewport: Viewport = { themeColor: "#f7f9fd" };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en"><body>{children}</body></html>; }
