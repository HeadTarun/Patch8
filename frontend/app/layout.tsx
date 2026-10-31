import type { Metadata } from "next";
import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import "./globals.css";
export const metadata: Metadata = { title: "PatchGuard — Find the flaw. Prove the fix.", description: "Upload C/C++ source for static analysis, review findings, and verify repair proposals." };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en"><body>{children}</body></html>; }
