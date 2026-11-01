"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { ArrowRight, Github, LoaderCircle, ShieldCheck } from "lucide-react";
import { Brand } from "@/components/brand";
import { getGitHubRepositories, scanGitHubRepository, type GitHubRepository } from "@/lib/api";

export default function AuthCallback() {
  const [error, setError] = useState("");
  const [checking, setChecking] = useState(true);
  const [authenticated, setAuthenticated] = useState(false);
  const [githubFlow, setGithubFlow] = useState(false);
  const [providerToken, setProviderToken] = useState("");
  const [repositories, setRepositories] = useState<GitHubRepository[]>([]);
  const [loadingRepositories, setLoadingRepositories] = useState(false);
  const [busyRepo, setBusyRepo] = useState("");
  const started = useRef(false);
  const [nextPage, setNextPage] = useState<number | null>(null);

  async function loadRepositories(token: string, page = 1) {
    setLoadingRepositories(true);
    setError("");
    try {
      const result = await getGitHubRepositories(token, page);
      setRepositories(current => page === 1 ? result.repositories : [...current, ...result.repositories.filter(repo => !current.some(existing => existing.full_name === repo.full_name))]);
      setNextPage(result.next_page);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load your public GitHub repositories.");
    } finally {
      setLoadingRepositories(false);
    }
  }

  async function scanRepository(repository: string) {
    setBusyRepo(repository);
    setError("");
    try {
      const result = await scanGitHubRepository(providerToken, repository);
      setProviderToken("");
      window.location.replace(`/app/analysis/${result.id}`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not start the GitHub scan.");
      setBusyRepo("");
    }
  }

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const accessToken = fragment.get("access_token");
    const githubToken = fragment.get("provider_token") || "";
    const params = new URLSearchParams(window.location.search);
    const isGithub = params.get("source") === "github";
    const oauthError = params.get("error_description");
    setGithubFlow(isGithub);
    window.history.replaceState(null, "", window.location.pathname);

    if (oauthError) {
      setError("GitHub sign-in did not complete. Check the Supabase GitHub provider settings and try again.");
      setChecking(false);
      return;
    }
    if (!accessToken) {
      setError(isGithub ? "GitHub sign-in did not return a session. Try again." : "The confirmation link is missing its session. Sign in to continue.");
      setChecking(false);
      return;
    }

    void (async () => {
      try {
        const response = await fetch("/api/auth/callback", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ access_token: accessToken }),
        });
        if (!response.ok) {
          const result = await response.json().catch(() => ({}));
          throw new Error(result.detail || "This confirmation link is invalid or expired.");
        }
        if (!isGithub) {
          window.location.replace("/app");
          return;
        }
        setAuthenticated(true);
        if (!githubToken) {
          setError("GitHub did not return an access token for public repositories. Sign in with GitHub again or continue to your workspace.");
          return;
        }
        setProviderToken(githubToken);
        await loadRepositories(githubToken);
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : "Could not complete sign in.");
      } finally {
        setChecking(false);
      }
    })();
  }, []);

  return (
    <main className="auth-wrap">
      <section className="auth-card github-callback-card panel" aria-live="polite">
        <Brand />
        <div className="eyebrow section-gap">{githubFlow ? "GITHUB REPOSITORY SCAN" : "ACCOUNT CONFIRMATION"}</div>
        <h1>{githubFlow ? "Choose a public repository" : error ? "Confirmation could not finish" : "Confirming your account"}</h1>
        <p className="muted">{githubFlow ? "Scan the latest commit on a repository’s default branch." : "Verifying your session with Supabase Auth…"}</p>

        {checking && <p className="muted" role="status"><LoaderCircle size={15} className="animate-spin" /> Verifying your session…</p>}
        {error && <p role="alert" className="error-state github-callback-error">{error}</p>}

        {githubFlow && authenticated && providerToken && <section className="github-repository-list section-gap" aria-label="Public GitHub repositories">
          {loadingRepositories ? <p className="muted" role="status"><LoaderCircle size={15} className="animate-spin" /> Loading public repositories…</p> : repositories.length ? repositories.map(repository => (
            <button key={repository.full_name} type="button" className="button github-repo-choice" onClick={() => void scanRepository(repository.full_name)} disabled={!!busyRepo}>
              <span><strong>{repository.full_name}</strong><small>Default branch: {repository.default_branch}</small>{repository.description && <small>{repository.description}</small>}</span>
              {busyRepo === repository.full_name ? <LoaderCircle size={15} className="animate-spin" /> : <ArrowRight size={15} />}
            </button>
          )) : <p className="muted">No public repositories were found on this GitHub account.</p>}
        </section>}

        {githubFlow && authenticated && <div className="toolbar section-gap">
          {error && providerToken && <button className="button" type="button" onClick={() => void loadRepositories(providerToken)} disabled={loadingRepositories}>Retry repository list</button>}
          {error && <a className="button" href="/api/auth/github">Reconnect GitHub</a>}
          <Link className="button primary" href="/app">Continue to workspace</Link>
        </div>}
        {!authenticated && error && <Link className="button primary" href="/login">Go to sign in</Link>}
        {githubFlow && <div className="status-pill"><Github size={13} /> Public repository access is read-only</div>}
        <div className="status-pill"><ShieldCheck size={13} /> Session uses a secure, HTTP-only cookie</div>
      </section>
      {nextPage && !busyRepo && <button className="button" disabled={loadingRepositories} onClick={() => void loadRepositories(providerToken, nextPage)}>Load more repositories</button>}
    </main>
  );
}
