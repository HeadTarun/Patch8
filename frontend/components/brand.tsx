export function Brand({ app = false }: { app?: boolean }) {
  return <a className="brand" href={app ? "/app" : "/"} aria-label="PatchProof home">
    <img className="brand-icon" src="/patchproof-logo.png" alt="PatchProof" style={{ height: "32px", width: "auto" }} />
  </a>;
}
