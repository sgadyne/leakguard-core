/** Presentation-only location groups, scoped to the current filtered page.
 * Sharing lines does not establish that observations refer to the same value. */
export type GroupableFinding = {
  id:string; rule?:string; severity?:string; source?:{path?:string}; path?:string; source_id?:string;
  start_line?:number; end_line?:number; part_id?:string;
};
export type FindingGroup<T extends GroupableFinding> = {id:string; findings:T[]; severity:string; rules:string[]};

export function groupFindings<T extends GroupableFinding>(findings:T[]):FindingGroup<T>[] {
  const groups = new Map<string, FindingGroup<T>>();
  const rank:Record<string,number> = {info:1, review:2, block:3};
  for (const finding of findings) {
    const path = finding.source?.path || finding.path;
    // Missing location data cannot prove coincidence. JSON keys avoid delimiter collisions.
    const valid = !!path && !!finding.part_id && Number.isInteger(finding.start_line) &&
      (finding.start_line || 0) > 0 && Number.isInteger(finding.end_line) &&
      (finding.end_line || 0) >= (finding.start_line || 0);
    const key = valid ? JSON.stringify([finding.source_id || '', path, finding.part_id, finding.start_line, finding.end_line]) : JSON.stringify(['ungrouped', finding.id]);
    let group = groups.get(key);
    if (!group) {
      group = {id:key, findings:[], severity:'', rules:[]};
      groups.set(key, group);
    }
    group.findings.push(finding);
    if (finding.rule && !group.rules.includes(finding.rule)) group.rules.push(finding.rule);
    // Unknown severity remains visible unless a block already establishes the maximum.
    const value = finding.severity || 'unknown';
    if (!group.severity || value === 'block' || (group.severity !== 'block' &&
      (!(value in rank) || ((group.severity in rank) && rank[value] > rank[group.severity])))) group.severity = value;
  }
  return [...groups.values()];
}
