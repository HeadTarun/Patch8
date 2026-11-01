export function Brand({ app = false }: { app?: boolean }) {
  return <a className="brand" href={app ? "/app" : "/"} aria-label="PatchProof home">
    <img className="brand-icon" src="/patchproof-mark.svg" alt="" />
    <span className="brand-wordmark"><span>Patch</span><span>Proof</span></span>
  </a>;
}
