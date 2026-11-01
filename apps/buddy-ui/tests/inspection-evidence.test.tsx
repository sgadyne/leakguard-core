import {test} from "node:test";
import assert from "node:assert/strict";
import {renderToStaticMarkup} from "react-dom/server";
import InspectionHealth, {ExecutionDiagnostics, availableEvidence} from "../src/InspectionEvidence";
import fixture from "../../../docs/standalone-overnight/fixtures/inspection-evidence.json";
const text=(value:unknown)=>renderToStaticMarkup(<InspectionHealth value={value}/>).replace(/<style[^>]*>[\s\S]*?<\/style>/g,"").replace(/<[^>]+>/g,"");
test("available encrypted-store contract fixture renders its observed age and counts",()=>{const e=fixture.cases.available.host.inspection_evidence;assert.ok(availableEvidence(e));const output=text(e);assert.match(output,/3 minutes/);assert.match(output,/2 with known age/);assert.match(output,/0 with unknown age/);assert.doesNotMatch(output,/Last successful reconciliation/);});
test("historical contract fixture keeps ages and last completion unknown",()=>{const output=text(fixture.cases.historical.host.inspection_evidence);assert.match(output,/0 with known age/);assert.match(output,/2 with unknown age/);assert.ok((output.match(/Not measured/g)||[]).length>=2);});
test("locked contract fixture and null measurement do not fabricate zero evidence",()=>{for(const e of [undefined,{schema_version:1,measured_at:null},{schema_version:2,measured_at:300}]){const output=text(e);assert.match(output,/Not measured/);assert.doesNotMatch(output,/0 with known age/);assert.doesNotMatch(output,/0 with unknown age/);}});
test("retained recovery has explicit label and unknown exception class",()=>{const e={...fixture.cases.available.host.inspection_evidence,diagnostics:[{code:"parser-failed",stage:"parse",exception_type:null,at:250,retry_count:1,recovered:true}]};const output=renderToStaticMarkup(<ExecutionDiagnostics value={e}/>);assert.match(output,/Recovered/);assert.match(output,/Exception type not recorded/);assert.match(output,/Stage progress is not measured/);});

test("diagnostics remain visible before chronology has a measured checkpoint",()=>{const e={schema_version:1,measured_at:null,diagnostics:[{code:"parser-failed",stage:"parse",exception_type:null,at:250,retry_count:0,recovered:false}]};const output=renderToStaticMarkup(<ExecutionDiagnostics value={e}/>);assert.match(output,/Needs attention/);assert.match(output,/parser-failed/);assert.match(output,/Exception type not recorded/);});
