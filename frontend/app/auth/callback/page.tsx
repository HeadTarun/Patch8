"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { LoaderCircle, ShieldCheck } from "lucide-react";
import { Brand } from "@/components/brand";

export default function AuthCallback() {
  const [error, setError] = useState("");

  useEffect(() => {
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const accessToken = fragment.get("access_token");
    const oauthError = new URLSearchParams(window.location.search).get("error_description");
    window.history.replaceState(null, "", window.location.pathname);

    if (oauthError) {
      setError("GitHub sign-in did not complete. Check the Supabase GitHub provider settings and try again.");
      return;
    }

    if (!accessToken) {
      setError("The confirmation link is missing its session. Sign in to continue.");
      return;
    }

    void fetch("/api/auth/callback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ access_token: accessToken }),
    })
      .then(async (response) => {
        if (!response.ok) {
          const result = await response.json().catch(() => ({}));
          throw new Error(result.detail || "This confirmation link is invalid or expired.");
        }
        window.location.replace("/app");
      })
      .catch((reason: unknown) => {
        setError(reason instanceof Error ? reason.message : "Could not complete sign in.");
      });
  }, []);

  return (
    <main className="auth-wrap">
      <section className="auth-card panel" aria-live="polite">
        <Brand />
        <div className="eyebrow section-gap">ACCOUNT CONFIRMATION</div>
        <h1>{error ? "Confirmation could not finish" : "Confirming your account"}</h1>
        {error ? (
          <>
            <p role="alert" className="error-state">{error}</p>
            <Link className="button primary" href="/login">Go to sign in</Link>
          </>
        ) : (
          <p className="muted"><LoaderCircle size={15} className="animate-spin" /> Verifying your email with Supabase Auth…</p>
        )}
        <div className="status-pill"><ShieldCheck size={13} /> Your token is exchanged securely, then removed from the address bar.</div>
      </section>
    </main>
  );
}
