export function Brand({ app = false }: { app?: boolean }) {
  return <a className="brand" href={app ? "/app" : "/"} aria-label="Patch8 home">
    <img className="brand-icon" src="/patchproof-mark.svg" alt="" />
    <span className="brand-wordmark"><span>Patch</span><span>8</span></span>
  </a>;
}
