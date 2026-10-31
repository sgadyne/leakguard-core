/** Value-free analyzer provenance already validated by the scanner protocol. */
export type FindingAnalysis = {
 schema_version:number; start:number; end:number; entity_type:string;
 score:number|null; recognizer_id:string; analyzer_id:string;
 analyzer_version:string; model_id:string;
};
export function analysisReason(analysis?:FindingAnalysis):string {
 switch(analysis?.entity_type){
  case "JOSE_COMPACT_JWE":return "Compact JWE structure matched: five segments with a consistent protected header and segment sizes. Cryptographic validity was not checked.";
  case "JOSE_COMPACT_JWS_CANDIDATE":return "Compact JWS structure matched. Signature authenticity was not checked.";
  case "JOSE_COMPACT_UNVERIFIED":return "Compact JOSE candidate with an unverified structure. Review the source privately.";
  default:return "The recognizer reported this entity and source span. Matched values are not shown.";
 }
}
