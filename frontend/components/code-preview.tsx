"use client";

type DiffRow = { oldLine?: number; newLine?: number; oldText?: string; newText?: string; kind: "context" | "change" | "add" | "remove" };

export function CodePreview({ text, line, startLine = 1, label }: { text: string; line?: number; startLine?: number; label?: string }) {
  return <pre className="source-preview" aria-label={label || "Source code preview"}>{text.split(/\r?\n/).map((value, index) => {
    const number = startLine + index;
    return <span className={`source-line ${number === line ? "source-line-highlight" : ""}`} key={index}><span className="source-line-number">{number}</span><span>{value || " "}</span></span>;
  })}</pre>;
}

function parseUnifiedDiff(diff: string): DiffRow[] {
  const lines = diff.split("\n");
  const rows: DiffRow[] = [];
  let oldLine = 1;
  let newLine = 1;
  let index = 0;
  while (index < lines.length) {
    const hunk = lines[index].match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (!hunk) { index++; continue; }
    oldLine = Number(hunk[1]);
    newLine = Number(hunk[2]);
    index++;
    while (index < lines.length && !lines[index].startsWith("@@ ")) {
      const value = lines[index];
      if (value.startsWith("\\ No newline")) { index++; continue; }
      if (value.startsWith(" ")) {
        rows.push({ oldLine: oldLine++, newLine: newLine++, oldText: value.slice(1), newText: value.slice(1), kind: "context" });
        index++;
        continue;
      }
      const removed: string[] = [];
      const added: string[] = [];
      while (index < lines.length && (lines[index].startsWith("-") || lines[index].startsWith("+"))) {
        if (lines[index].startsWith("-")) removed.push(lines[index++].slice(1));
        else added.push(lines[index++].slice(1));
      }
      const count = Math.max(removed.length, added.length);
      for (let row = 0; row < count; row++) {
        const oldText = removed[row];
        const newText = added[row];
        rows.push({ oldLine: oldText === undefined ? undefined : oldLine++, newLine: newText === undefined ? undefined : newLine++,
          oldText, newText, kind: oldText === undefined ? "add" : newText === undefined ? "remove" : "change" });
      }
      if (!removed.length && !added.length) index++;
    }
  }
  return rows;
}

export function RepairDiffPreview({ diff }: { diff: string }) {
  const rows = parseUnifiedDiff(diff);
  return <div className="repair-diff-table-wrap" role="region" aria-label="Side-by-side repair diff" tabIndex={0}>
    <table className="repair-diff-table"><thead><tr><th colSpan={2}>Original</th><th colSpan={2}>Proposed</th></tr></thead>
      <tbody>{rows.map((row, index) => <tr key={index} className={`repair-diff-row repair-diff-${row.kind}`}>
        <td className="repair-diff-number">{row.oldLine ?? ""}</td><td className="repair-diff-code">{row.oldText ?? ""}</td>
        <td className="repair-diff-number">{row.newLine ?? ""}</td><td className="repair-diff-code">{row.newText ?? ""}</td>
      </tr>)}</tbody>
    </table>
  </div>;
}

export function UnifiedDiffPreview({ diff }: { diff: string }) {
  return <pre className="unified-diff-preview" aria-label="Unified repair diff">{diff.split("\n").map((line, index) => {
    const kind = line.startsWith("+") && !line.startsWith("+++") ? "add" : line.startsWith("-") && !line.startsWith("---") ? "remove" : line.startsWith("@@") ? "hunk" : "";
    return <span className={`unified-diff-line ${kind ? `unified-diff-${kind}` : ""}`} key={index}>{line || " "}</span>;
  })}</pre>;
}
