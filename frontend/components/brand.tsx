import { ShieldCheck } from "lucide-react";
export function Brand({ app = false }: { app?: boolean }) { return <a className="brand" href={app ? "/app" : "/"}><span className="brand-icon"><ShieldCheck size={17} /></span><span>PatchGuard</span></a>; }
