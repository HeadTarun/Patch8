import { Code2, ShieldCheck } from "lucide-react";

export function ScanParticles() {
  return (
    <div className="scan-particle-scene" aria-hidden="true">
      <div className="scan-preview-card">
        <div className="scan-preview-head">
          <span className="scan-preview-icon"><Code2 size={16} /></span>
          <div className="scan-preview-file"><span>SAMPLE SCAN</span><strong>src/parser.c</strong></div>
          <span className="scan-state-pill"><i /> ANALYZING</span>
        </div>
        <pre className="scan-preview-code"><span>82</span> <code>char name[64];</code>{"\n"}<span>83</span> <code>...</code>{"\n"}<span>84</span> <code className="scan-code-risk">strcpy(name, input);</code></pre>
        <div className="scan-preview-result">
          <div><span className="scan-preview-risk">CWE-120</span><span>Buffer operation flagged</span></div>
          <span className="scan-preview-verified"><ShieldCheck size={15} /> Review required</span>
        </div>
        <div className="scan-preview-progress"><span /></div>
      </div>
    </div>
  );
}
