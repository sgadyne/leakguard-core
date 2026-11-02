import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Alert, AppBar, Box, Button, Chip, CircularProgress, CssBaseline, Dialog, DialogActions, DialogContent, DialogTitle,
  Divider, Drawer, FormControl, FormControlLabel, IconButton, InputLabel, LinearProgress, MenuItem, Paper, Select,
  Snackbar, Stack as MuiStack, Switch, Tab, Tabs, TextField as MuiTextField, ThemeProvider, Toolbar, Typography as MuiTypography, createTheme
} from "@mui/material";
import { Add, Lock, FolderOpen, Dashboard, Search, VpnKey, Extension, Settings as SettingsIcon, Refresh, Close, ChevronRight, ArrowUpward, PlayArrow, Pause, Stop, DeleteOutlined, Tune, Timeline } from "@mui/icons-material";
import InspectionHealth, { ExecutionDiagnostics } from "./InspectionEvidence";
import { PageHeader, EvidenceMetric, StoreBadge } from "./workbench";
import BrandMark from './BrandMark';
import { AgGridReact } from "ag-grid-react";
import { AllCommunityModule, ModuleRegistry, themeQuartz } from "ag-grid-community";
import { initializeSession, request, setConnectionHandlers } from "./api";
import Screens from "./Screens";
import VMLocations from "./VMLocations";
const Stack: any = ({ alignItems, justifyContent, gap, ...props }: any) => <MuiStack {...props} sx={{ alignItems, justifyContent, gap, ...props.sx }} />;
const Typography: any = ({ fontWeight, fontSize, display, ...props }: any) => <MuiTypography {...props} sx={{ fontWeight, fontSize, display, ...props.sx }} />;
const TextField: any = ({ inputProps, ...props }: any) => <MuiTextField {...props} slotProps={{ ...(props.slotProps || {}), htmlInput: inputProps }} />;
ModuleRegistry.registerModules([AllCommunityModule]);

type Page = "activity" | "overview" | "sources" | "findings" | "vault" | "plugins" | "settings";
type Source = { id: string; label?: string; root: string; kind?: string; enabled?: boolean; schedule_seconds?: number | null; last_success_at?: string | null; exclusions?: string[]; managed_inventory?:boolean; availability?:string; target?:string; schedule?:any; next_run_at?:string };
type Job = { id: string; source_id: string; state: string; files_scanned?: number | null; pending_files?: number | null; pending_directories?: number | null; coverage?: string; last_error?: string; created_at?:string; updated_at?: string };
type Root = { name?: string; path: string; kind?: string; status?: string; selectable?: boolean };
const nav: { id: Page; label: string; icon: React.ReactNode }[] = [
  { id: "activity", label: "Activity", icon: <Timeline fontSize="small" /> },
  { id: "overview", label: "Overview", icon: <Dashboard fontSize="small" /> }, { id: "sources", label: "Sources", icon: <FolderOpen fontSize="small" /> },
  { id: "findings", label: "Findings", icon: <Search fontSize="small" /> }, { id: "vault", label: "Credential vault", icon: <VpnKey fontSize="small" /> },
  { id: "plugins", label: "Plugins", icon: <Extension fontSize="small" /> }, { id: "settings", label: "Settings", icon: <SettingsIcon fontSize="small" /> }
];
const colors = {
 light: { canvas:"#F4F6F3", surface:"#FFFFFF", sidebar:"#F9FBF8", subtle:"#EDF2EE", text:"#173B43", muted:"#586F72", info:"#385E7E", infoTint:"#EAF1F8", border:"#DCE5DF", accent:"#2D6B68", accentHover:"#225451", accentTint:"#E4F1EA", danger:"#A13F3D", warning:"#85581C", success:"#2D6B68", focus:"#2D6B68" },
 dark: { canvas:"#10262E", surface:"#17323B", sidebar:"#132C34", subtle:"#203E46", text:"#ECF3EF", muted:"#AEC3C3", info:"#BCD5EF", infoTint:"#2A425B", border:"#345159", accent:"#A9DDC9", accentHover:"#C1EADB", accentTint:"#244D49", danger:"#F1B7AD", warning:"#F1D39B", success:"#A9DDC9", focus:"#A9DDC9" }
};
const pageTitle: Record<Page,string> = { activity:"Activity", overview:"Overview", sources:"Sources", findings:"Findings", vault:"Credential vault", plugins:"Plugins", settings:"Settings" };
const activeJob = (job: Job) => ["queued","running","backoff"].includes(job.state);
const apiMessages:Record<string,string>={"source-unavailable":"Source is offline or unavailable.","state-checkpoint-failed":"Encrypted scan progress could not be saved.","scan-progress-stalled":"The scan stopped after repeated slices without progress.","permission-denied":"Permission to read this source was denied.","scheduler-failed":"The background scheduler stopped unexpectedly."};
const dateText = (value?: string | null) => value ? new Date(value).toLocaleString() : "Not yet checked";
const coverageText = (value?: string | null) => value === "complete" ? "Complete" : value === "incomplete" ? "Incomplete" : value === "unknown" ? "Unknown" : value || "Not yet checked";
const jobStateLabel=(value?:string)=>({queued:"Queued",running:"Scanning",paused:"Paused",backoff:"Retrying",completed:"Completed",cancelled:"Cancelled",failed:"Failed"} as Record<string,string>)[value||""]||value||"Not yet checked";
const scheduleText = (value?: number | null) => !value ? "Global schedule" : value === 3600 ? "Hourly" : value === 21600 ? "Every 6 hours" : value === 86400 ? "Every 24 hours" : value === 604800 ? "Weekly" : "Every " + Math.round(value / 60) + " minutes";
const availabilityText=(value?:string)=>({available:"Available",offline:"Offline","source-unavailable":"Unavailable","permission-denied":"Permission denied","identity-changed":"Identity changed",unverified:"Not checked",unknown:"Not measured","platform-unavailable":"Unavailable on this platform"} as Record<string,string>)[value||""]||"Not measured";
const sourceScheduleSeconds = (source?: Source | null) => source?.schedule?.mode === "daily" ? -1 : Number(source?.schedule?.interval_seconds ?? source?.schedule_seconds) || 0;
const sourceScheduleText = (source: Source) => source.schedule?.mode === "daily" ? "Daily at " + source.schedule.daily_time + " " + source.schedule.timezone : scheduleText(sourceScheduleSeconds(source));

export default function App() {
  const [appearance, setAppearance] = useState<"system"|"light"|"dark">(() => {const saved=localStorage.getItem("buddy-theme");return saved==="light"||saved==="dark"||saved==="system"?saved:"system"});
  const [credentialPrefill, setCredentialPrefill] = useState<any>(null);
  const [page, setPage] = useState<Page>(() => {const route=location.hash.slice(1) as Page;return nav.some(n=>n.id===route)?route:"overview"});
  const [sessionReady, setSessionReady] = useState(false);
  const [sessionError, setSessionError] = useState("");
  const [connected, setConnected] = useState(false);
  const [status, setStatus] = useState<any>(null);
  const [sources, setSources] = useState<Source[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [selectedSource, setSelectedSource] = useState<string>("");
  const [sourceTab, setSourceTab] = useState(0);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [addedSourceId,setAddedSourceId]=useState("");
  const [error, setError] = useState("");
  const [addOpen, setAddOpen] = useState(false);
  const [roots, setRoots] = useState<Root[]>([]);
  const [root, setRoot] = useState<Root | null>(null);
  const [browsePath, setBrowsePath] = useState("");
  const [browseEntries, setBrowseEntries] = useState<any[]>([]);
  const [browseCursor, setBrowseCursor] = useState<string | null>(null);
  const [browseStatus,setBrowseStatus]=useState("available");
  const [browseRoot, setBrowseRoot] = useState("");
  const [sourceLabel, setSourceLabel] = useState("");
  const [schedule, setSchedule] = useState(0);
  const [exclusions, setExclusions] = useState("");
  const [manualRoot, setManualRoot] = useState("");
  const [locationKind,setLocationKind]=useState("local");
  const [gateOpen, setGateOpen] = useState(false);
  const [gateTarget, setGateTarget] = useState<"observations"|"observations-create">("observations");
  const [passphrase, setPassphrase] = useState("");
  const [passphraseConfirm, setPassphraseConfirm] = useState("");
  const [themeMode, setThemeMode] = useState<"light"|"dark">("light");
  const [mobileDrawer, setMobileDrawer] = useState(false);
  const busyRef = useRef(false);
  const revealGeneration = useRef(0);
  const refreshGeneration = useRef(0);

  const resolvedTheme = appearance === "system" ? (window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light") : appearance;
  useEffect(() => {
    if (window.buddyDesktop) window.buddyDesktop.getPreferences().then(p => setAppearance(p.theme)).catch(() => undefined);
    const listener = () => setThemeMode(appearance === "system" ? (window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light") : appearance);
    listener();
    const media = window.matchMedia?.("(prefers-color-scheme: dark)");
    media?.addEventListener("change", listener);
    return () => media?.removeEventListener("change", listener);
  }, [appearance]);
  useEffect(() => { setThemeMode(resolvedTheme); }, [resolvedTheme]);
  const palette = colors[themeMode];
  const muiTheme = useMemo(() => createTheme({
    cssVariables:true,
    palette: { mode: themeMode, primary: { main: palette.accent, dark: palette.accentHover, contrastText: themeMode === "dark" ? "#10262A" : "#FFFFFF" }, background: { default: palette.canvas, paper: palette.surface }, text: { primary: palette.text, secondary: palette.muted }, divider: palette.border, info:{main:palette.info},error:{main:palette.danger}, warning:{main:palette.warning}, success:{main:palette.success} },
    typography: { fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif', fontSize: 14, h1:{fontSize:28,lineHeight:"36px",fontWeight:650}, h2:{fontSize:18,lineHeight:"26px",fontWeight:600}, h3:{fontSize:16,lineHeight:"24px",fontWeight:600}, body2:{fontSize:14,lineHeight:"21px"},caption:{fontSize:12,lineHeight:"18px"},overline:{fontSize:11,lineHeight:"22px",fontWeight:600,letterSpacing:".035em"} },
    shape: { borderRadius: 8 }, components: { MuiAlert:{styleOverrides:{root:{borderRadius:8,"&.MuiAlert-colorInfo":{backgroundColor:palette.infoTint,color:palette.text}}}},MuiTab:{styleOverrides:{root:{textTransform:"none",fontWeight:600}}},MuiChip:{styleOverrides:{root:{fontSize:12,fontWeight:600}}}, MuiButton:{styleOverrides:{root:{minHeight:36,height:"auto",textTransform:"none",fontWeight:600,boxShadow:"none",padding:"8px 16px"},outlined:{borderColor:palette.border,color:palette.text,"&:hover":{borderColor:palette.accent,backgroundColor:palette.accentTint}}}}, MuiOutlinedInput:{styleOverrides:{root:{minHeight:36}}}, MuiPaper:{styleOverrides:{root:{backgroundImage:"none"}}}, MuiCssBaseline:{styleOverrides:{"*":{boxSizing:"border-box"},"::selection":{backgroundColor:palette.accentTint}}}}
  }), [themeMode,palette]);
  const refreshStatus = useCallback(async () => {
    const generation=++refreshGeneration.current;
    const data = await request<any>("/status");
    if(generation!==refreshGeneration.current)return;
    const observation = data.observations || {};
    if (observation.unlocked) {
      const [ss, jj] = await Promise.all([request<any>("/sources"), request<any>("/jobs")]);
      if(generation!==refreshGeneration.current)return;
      setSources(Array.isArray(ss) ? ss : ss.sources || []);
      setJobs(Array.isArray(jj) ? jj : jj.jobs || []);
    } else { setSources([]); setJobs([]); setSelectedSource(""); }
    setStatus(data);setConnected(true);
  }, []);
  const refreshAll = useCallback(async () => {
    try { await refreshStatus(); setError(""); }
    catch (e) { refreshGeneration.current++; setConnected(false); setStatus(null); setSources([]); setJobs([]); setSelectedSource(""); scrubSensitive(); setError((e as Error).message || "Password Buddy is unavailable."); }
  }, [refreshStatus]);
  useEffect(() => {
    let alive = true;
    initializeSession().then(() => { if (alive) { setSessionReady(true); setSessionError(""); } }).catch(e => { if (alive) setSessionError((e as Error).message); });
    setConnectionHandlers(() => { refreshGeneration.current++; setConnected(false); setStatus(null); setSources([]); setJobs([]); setSelectedSource(""); setError("Backend connection unavailable. Retry to refresh live data."); scrubSensitive(); }, () => { setConnected(true); });
    return () => { alive = false; };
  }, []);
  useEffect(() => { if (sessionReady) void refreshAll(); }, [sessionReady, refreshAll]);
  useEffect(() => { if (sources.length && (!selectedSource || !sources.some(s=>s.id===selectedSource))) setSelectedSource(sources[0].id); }, [sources,selectedSource]);
  useEffect(() => {
    if (!sessionReady) return;
    let timer: number;
    let inFlight = false;
    const poll = async () => { if (inFlight) return; inFlight = true; try { await refreshAll(); } finally { inFlight = false; timer = window.setTimeout(poll, document.visibilityState === "visible" ? 2000 : 5000); } };
    timer = window.setTimeout(poll, document.visibilityState === "visible" ? 2000 : 5000);
    return () => window.clearTimeout(timer);
  }, [sessionReady, refreshAll]);
  useEffect(() => {
    if (location.hash) setPage(location.hash.slice(1) as Page);
    const fn = () => { const value = location.hash.slice(1) as Page; if (nav.some(n=>n.id===value)) navigate(value); };
    window.addEventListener("hashchange", fn);
    const off = window.buddyDesktop?.onEvent(event => {
      if (event.type === "navigate") navigate(event.page);
      if (event.type === "clear-sensitive" && event.reason !== "blur" || event.type === "vault-locked") scrubSensitive();
      if (event.type === "backend-state" && event.state !== "ready") { refreshGeneration.current++; scrubSensitive(); setStatus(null); setSources([]); setJobs([]); setSelectedSource(""); setConnected(false); setError("Backend connection unavailable. Retry to refresh live data."); }
    });
    const blur = () => { if (document.activeElement instanceof HTMLElement) document.activeElement.blur(); };
    window.addEventListener("blur", blur);
    return () => { window.removeEventListener("hashchange", fn); window.removeEventListener("blur", blur); off?.(); };
  }, []);
  function scrubSensitive() { revealGeneration.current++; setPassphrase(""); setPassphraseConfirm(""); }
  function addFindingToVault(f:any) { navigate("vault"); setCredentialPrefill({title:((f.rule||"Finding")+" - "+(f.source?.path||f.path||"source").split(/[\\/]/).pop()).slice(0,256),location:f.source?.path||f.path||"",finding_id:f.id}); }
  function navigate(next: Page) { scrubSensitive(); if(next!=="vault")setCredentialPrefill(null); setPage(next); setMobileDrawer(false); history.replaceState(null,"","#"+next); if (next==="sources") setSourceTab(0); }
  async function run(action: () => Promise<void>) { if(busyRef.current)return;busyRef.current=true;setBusy(true); setError(""); try { await action(); } catch (e) { setError((e as Error).message || "Request failed."); } finally { busyRef.current=false;setBusy(false); } }
  function openGate(target: "observations"|"observations-create") { setGateTarget(target); setPassphrase(""); setPassphraseConfirm(""); setGateOpen(true); }
  async function submitGate() {
    if (gateTarget === "observations-create" && passphrase !== passphraseConfirm) throw new Error("Passphrases do not match.");
    if (passphrase.length < 12) throw new Error("Passphrases must contain at least 12 characters.");
    try { await request("/observations/" + (gateTarget === "observations-create" ? "create" : "unlock"), "POST", {passphrase}); } catch(e) { setPassphrase(""); setPassphraseConfirm(""); throw e; }
    setPassphrase(""); setPassphraseConfirm(""); setGateOpen(false); await refreshAll();
    setNotice(gateTarget === "observations-create" ? "Encrypted scan storage created." : "Scan storage unlocked.");
  }
  async function openAddSource() {
    setAddOpen(true);setBrowseStatus("unverified"); setRoot(null); setBrowsePath(""); setBrowseEntries([]); setBrowseCursor(null); setSourceLabel(""); setSchedule(0); setExclusions("");
    const list = await request<any>("/roots"); setRoots(Array.isArray(list) ? list : list.roots || []);
  }
  async function loadBrowse(path: string, rootPath: string, cursor?: string, append = false) {
    const q = new URLSearchParams({path, root:rootPath}); if (cursor) q.set("cursor",cursor);
    const result = await request<any>("/browse?" + q.toString());
    setBrowsePath(result.path || path); setBrowseRoot(rootPath); setBrowseStatus(result.status||"available");
    const unusable=["offline","permission-denied","unreadable","not-directory","directory-changed","platform-unavailable"].includes(result.status||"");
    setBrowseEntries(unusable?[]:append ? old => [...old, ...(result.entries || [])] : result.entries || []);
    setBrowseCursor(unusable?null:result.next_cursor || null);
    if (!root) setRoot({path:rootPath,kind:rootPath.startsWith("\\\\") ? "unc" : "local"});
  }
  async function pickNativeRoot(){const desktop=window.buddyDesktop;if(!desktop)throw new Error("Native folder picker is unavailable.");const info=await desktop.getInfo();if(!info.capabilities.directoryPicker)throw new Error("Native folder picker is unavailable.");const picked=await desktop.chooseDirectory();if(!picked.canceled&&picked.path){setManualRoot(picked.path);await chooseRoot(picked.path,"local");}}
  async function chooseRoot(path: string, kind = "local") {
    setBrowseStatus("checking");setRoot({path,kind}); setLocationKind(kind==="mounted"||path.startsWith("/Volumes/")?"mounted":"local"); setBrowseRoot(path);
    await loadBrowse(path,path);
  }
  async function saveSource(e: React.FormEvent) {
    e.preventDefault(); if (!root) throw new Error("Select a source folder first.");
    const relativeExclusions = exclusions.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
    if (relativeExclusions.length > 100) throw new Error("Use at most 100 exclusion paths.");
    const payload: any = {root:root.path, kind:locationKind, exclusions:relativeExclusions};
    if (sourceLabel.trim()) payload.label = sourceLabel.trim();
    if (schedule > 0) payload.schedule_seconds = schedule;
    const added=await request<Source>("/sources","POST",payload);
    setAddOpen(false); await refreshAll(); setAddedSourceId(added.id||""); setNotice("Location added. Automatic reconciliation is scheduled.");
  }
  async function startScan(id: string) { if(scanStorageIssue)throw new Error("New scans are paused because encrypted scan progress needs attention."); await request("/scans","POST",{source_id:id}); await refreshAll(); setNotice("Scan queued."); }
  async function setSourceEnabled(s: Source) { await request("/sources/"+encodeURIComponent(s.id),"PATCH",{enabled:s.enabled===false}); await refreshAll(); }
  async function updateSourceSchedule(s:Source,value:number) { await request("/sources/"+encodeURIComponent(s.id),"PATCH",{schedule_seconds:value||null}); await refreshAll(); }
  async function removeSource(s: Source) { if (!window.confirm("Remove this source and its schedule? Scan history is retained.")) return; await request("/sources/"+encodeURIComponent(s.id),"DELETE",{}); setSelectedSource(""); await refreshAll(); }
  async function jobAction(job: Job, action: "pause"|"resume"|"cancel") { if(action==="resume"&&scanStorageIssue)throw new Error("New scans are paused because encrypted scan progress needs attention."); await request("/jobs/"+encodeURIComponent(job.id)+"/"+action,"POST",{}); await refreshAll(); }
  const selected = sources.find(s=>s.id===selectedSource) || sources[0];
  const unreadableStatus = !sessionReady ? "" : sessionError || (!connected && !error ? "Connecting to Password Buddy" : "");
  const scanGate = status?.observations?.unlocked !== true;
  const scanStorageIssue=status?.observations?.healthy===false||Boolean(status?.host?.storage_error);
  const sourceRows = sources;
  const drawer = <Box sx={{width:216,height:"100vh",position:"sticky",top:0,display:"flex",flexDirection:"column",bgcolor:palette.sidebar,borderRight:"1px solid",borderColor:"divider"}}>
    <Box sx={{px:2.5,py:2.3,display:"flex",alignItems:"center",gap:1.25}}><BrandMark size={36}/><Box><Typography fontWeight={700} fontSize={14} sx={{lineHeight:1.3}}>Password<br/>Buddy</Typography></Box></Box>
    <Divider/>
    <Box component="nav" aria-label="Main navigation" sx={{p:2,pt:4,display:"grid",gap:1}}>{[...nav].sort((a,b)=>["overview","findings","sources","activity","vault","settings","plugins"].indexOf(a.id)-["overview","findings","sources","activity","vault","settings","plugins"].indexOf(b.id)).map(item=><Button key={item.id} onClick={()=>navigate(item.id)} startIcon={item.icon} fullWidth aria-current={page===item.id?"page":undefined} sx={{justifyContent:"flex-start",minHeight:40,color:page===item.id?"primary.main":"text.secondary",bgcolor:page===item.id?palette.accentTint:"transparent"}}>{item.label}</Button>)}</Box>
    <Box sx={{mt:"auto",p:3,borderTop:"1px solid",borderColor:"divider"}}><Stack spacing={1.25} color="text.secondary"><StoreBadge name="Scan storage" store={status?.observations}/><StoreBadge name="Credential vault" store={status?.vault}/><Box sx={{pt:2}}><Typography variant="overline">Local workspace</Typography><Typography variant="body2" fontWeight={600}>Private to this device</Typography></Box></Stack></Box>
  </Box>;

  if (!sessionReady && !sessionError) return <ThemeProvider theme={muiTheme}><CssBaseline/><Box sx={{height:"100vh",display:"grid",placeItems:"center"}}><Stack alignItems="center" spacing={2}><CircularProgress/><Typography>Opening Password Buddy</Typography></Stack></Box></ThemeProvider>;

  return <ThemeProvider theme={muiTheme}><CssBaseline/><a href="#main-content" className="skip-link" onClick={e=>{e.preventDefault();document.getElementById("main-content")?.focus()}}>Skip to content</a>
    <Box sx={{display:"flex",minHeight:"100vh",bgcolor:"background.default","--buddy-focus":palette.focus}}>
      <Box sx={{display:{xs:"none",md:"block"}}}>{drawer}</Box>
      <Drawer open={mobileDrawer} onClose={()=>setMobileDrawer(false)}>{drawer}</Drawer>
      <Box sx={{flex:1,minWidth:0}}>
        <AppBar position="sticky" color="inherit" elevation={0} sx={{borderBottom:"1px solid",borderColor:"divider",bgcolor:"background.default"}}>
          <Toolbar sx={{minHeight:"56px !important",px:"32px !important",gap:2}}><IconButton onClick={()=>setMobileDrawer(true)} sx={{display:{md:"none"}}} aria-label="Open navigation"><Tune/></IconButton><Typography variant="overline" color="text.secondary" sx={{flex:1}}>Workspace / {pageTitle[page] || "Overview"}</Typography><Chip size="small" label={connected?"Connected":"Unavailable"} color={connected?"success":"default"} variant="outlined"/><IconButton aria-label="Refresh" onClick={()=>void refreshAll()}><Refresh/></IconButton></Toolbar>
        </AppBar>
        <Box component="main" id="main-content" tabIndex={-1} sx={{p:{xs:"24px",lg:"24px 32px 40px"},maxWidth:1540,mx:"auto"}}>
          {unreadableStatus && <Alert severity={sessionError?"error":"info"} sx={{mb:2}} action={sessionError ? undefined : <Button onClick={()=>void refreshAll()}>Retry</Button>}>{unreadableStatus}</Alert>}
          {status && scanStorageIssue && <Alert severity="error" sx={{mb:2,whiteSpace:"pre-line"}}>Encrypted scan progress needs attention{status?.host?.storage_error?". Details: "+status.host.storage_error:"."} New scans are paused until storage health is restored.</Alert>}
          {error && <Alert severity="error" sx={{mb:2}} onClose={()=>setError("")}>{error}</Alert>}
          {!sessionError && !status && !error && <Alert severity="info" sx={{mb:2}} action={<Button onClick={()=>void refreshAll()}>Retry</Button>}>Waiting for a live Password Buddy connection.</Alert>}
          {!sessionError && !status && error && <Alert severity="warning" sx={{mb:2}} action={<Button onClick={()=>void refreshAll()}>Retry</Button>}>Backend data is unavailable. Live workspace panels are hidden until the connection returns.</Alert>}
          {!sessionError && status && page==="overview" && <Overview sources={sourceRows} jobs={jobs} status={status} locked={scanGate} scanDisabled={scanStorageIssue||busy} onUnlock={()=>openGate(status?.observations?.created?"observations":"observations-create")} onSources={()=>navigate("sources")} onAdd={()=>void run(openAddSource)} onScan={id=>void run(()=>startScan(id))} onJobAction={(j,a)=>void run(()=>jobAction(j,a))}/>}
          {!sessionError && status && page==="sources" && <>
            <PageIntro eyebrow="LOCAL FOLDERS AND SHARES" title="Sources" text="This Mac is discovered automatically. Add external drives or OS-mounted shares, then review inspection progress and gaps." action={<Button variant="contained" startIcon={<Add/>} onClick={()=>void run(openAddSource)}>Add source</Button>}/>
            {scanGate ? <StorageGate created={status?.observations?.created} kind="scan" onClick={()=>openGate(status?.observations?.created?"observations":"observations-create")}/> : <>
              <Tabs value={sourceTab} onChange={(_,v)=>setSourceTab(v)} sx={{mb:2}}><Tab label="Sources"/><Tab label="Scan activity"/><Tab label="Git guards"/><Tab label="VM locations"/></Tabs>
              {sourceTab===0 && <Box sx={{display:"grid",gridTemplateColumns:{xs:"minmax(0,1fr)",lg:"minmax(0,1fr) 300px"},gap:2,alignItems:"start"}}>
                <SourceTable sources={sources} jobs={jobs} scanDisabled={scanStorageIssue||busy} selected={selected?.id} onSelect={s=>setSelectedSource(s.id)} onScan={s=>void run(()=>startScan(s.id))}/>
                <SourceInspector source={selected} jobs={jobs} scanDisabled={scanStorageIssue||busy} onSchedule={(s,v)=>void run(()=>updateSourceSchedule(s,v))} onScan={s=>void run(()=>startScan(s.id))} onEnable={s=>void run(()=>setSourceEnabled(s))} onRemove={s=>void run(()=>removeSource(s))}/>
              </Box>}
              {sourceTab===1 && <JobList jobs={jobs} sources={sources} scanDisabled={scanStorageIssue||busy} onAction={(j,a)=>void run(()=>jobAction(j,a))}/>}
              {sourceTab===2 && <GitPlaceholder/>}{sourceTab===3 && <VMLocations unlocked={!scanGate} onRefresh={()=>void refreshAll()} onError={setError}/>}
            </>}
          </>}
          {!sessionError && status && page==="activity" && <><PageIntro eyebrow="RECORDED WORK" title="Activity" text="Scan slices, source coverage and retained execution diagnostics."/>{scanGate?<StorageGate created={status?.observations?.created} kind="scan" onClick={()=>openGate(status?.observations?.created?"observations":"observations-create")}/>:<Stack spacing={2.5}><JobList jobs={jobs} sources={sources} scanDisabled={scanStorageIssue||busy} onAction={(j,a)=>void run(()=>jobAction(j,a))}/><ExecutionDiagnostics value={status.host?.inspection_evidence}/></Stack>}</>}
          {!sessionError && status && ["findings","vault","plugins","settings"].includes(page) && <Screens page={page} status={status} onRefresh={()=>void refreshAll()} appearance={appearance} onAppearance={v=>setAppearance(v)} onAddToVault={addFindingToVault} prefill={credentialPrefill} onClearPrefill={()=>setCredentialPrefill(null)} />}
        </Box>
      </Box>
    </Box>
    <Dialog open={gateOpen} onClose={()=>{setGateOpen(false);setPassphrase("");setPassphraseConfirm("");}} fullWidth maxWidth="xs">
      <DialogTitle>{gateTarget==="observations-create"?"Create encrypted scan storage":"Unlock scan storage"}</DialogTitle>
      <DialogContent>{error&&<Alert severity="error" sx={{my:1}}>{error}</Alert>}<Stack spacing={2} sx={{pt:1}}><Typography variant="body2">{gateTarget==="observations-create"?"Scan history and review notes are encrypted separately from the credential vault.":"Unlock the observation store to browse sources, jobs and findings."}</Typography>{gateTarget==="observations-create"&&<Alert severity="info">Automatic This Mac coverage starts after scan storage is created. Change schedules, exclusions and pause controls in Settings. Cloud placeholders and encrypted credential stores are inventoried without opening them.</Alert>}<TextField type="password" label="Passphrase" value={passphrase} onChange={(e:any)=>setPassphrase(e.target.value)} inputProps={{maxLength:1024,autoComplete:"new-password"}} autoFocus/><Typography variant="caption" color="text.secondary">{gateTarget==="observations-create"?"Use 12 to 1024 characters.":"Passphrase is held only for this action."}</Typography>{gateTarget==="observations-create"&&<TextField type="password" label="Confirm passphrase" value={passphraseConfirm} onChange={(e:any)=>setPassphraseConfirm(e.target.value)} inputProps={{maxLength:1024,autoComplete:"new-password"}}/>}</Stack></DialogContent>
      <DialogActions><Button onClick={()=>{setPassphrase("");setPassphraseConfirm("");setGateOpen(false);}}>Cancel</Button><Button variant="contained" disabled={busy} onClick={()=>void run(submitGate)}>Continue</Button></DialogActions>
    </Dialog>
    <Dialog open={addOpen} onClose={()=>setAddOpen(false)} fullWidth maxWidth="md">
      <DialogTitle sx={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>Add a source<IconButton aria-label="Close" onClick={()=>setAddOpen(false)}><Close/></IconButton></DialogTitle>
      <DialogContent dividers>{error&&<Alert severity="error" sx={{mb:2}}>{error}</Alert>}
        {!root ? <Stack spacing={2}>
          <Typography variant="body2" color="text.secondary">Choose a common location, or enter a folder path. Buddy will inspect only the selected root.</Typography>
          <Box sx={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(230px,1fr))",gap:1}}>{roots.map((item,i)=><Button key={item.path+i} variant="outlined" disabled={item.selectable===false||["offline","permission-denied","platform-unavailable"].includes(item.status||"")} onClick={()=>void run(()=>chooseRoot(item.path,item.kind||"local"))} sx={{justifyContent:"flex-start",textAlign:"left",p:1.5}}><Stack alignItems="flex-start"><Typography fontWeight={600}>{item.name||item.path}</Typography><Typography variant="caption" className="path-text">{item.status||"Available"}  {item.path}</Typography></Stack></Button>)}</Box>
          <Divider>or enter path</Divider><Stack direction="row" spacing={1}><TextField label="Folder or mounted share" fullWidth value={manualRoot} onChange={(e:any)=>setManualRoot(e.target.value)} inputProps={{maxLength:4096}} placeholder="/path/to/folder or \\\\server\\share"/><Button variant="outlined" onClick={()=>void run(()=>chooseRoot(manualRoot.trim(),manualRoot.trim().startsWith("\\\\")?"unc":"local"))}>Browse</Button>{window.buddyDesktop&&<Button variant="outlined" onClick={()=>void run(pickNativeRoot)}>Choose folder</Button>}</Stack>
        </Stack> : <Stack spacing={2}>
          <Stack direction="row" spacing={1} alignItems="center"><Button size="small" onClick={()=>{setRoot(null);setBrowseEntries([]);}}>Choose another root</Button><Typography variant="body2" className="path-text">{browsePath || root.path}</Typography><Chip size="small" variant="outlined" label={"Selected scope: "+root.path}/></Stack>{browseStatus!=="available"&&<Alert severity="warning">{browseStatus==="directory-changed"?"Folder changed; browse it again.":browseStatus==="permission-denied"?"Permission denied for this folder.":browseStatus==="offline"?"This location is offline.":browseStatus==="platform-unavailable"?"This location is unavailable on this platform.":"Folder status: "+browseStatus}</Alert>}
          <Stack direction="row" spacing={1}><Button variant="outlined" size="small" disabled={browsePath===browseRoot} onClick={()=>void run(()=>{const p=browsePath.replace(/[\\/]+$/,""); const sep=p.includes("\\")?"\\":"/"; const parts=p.split(/[\\/]/); parts.pop(); const parent=parts.join(sep)||sep; return loadBrowse(parent,browseRoot);})} startIcon={<ArrowUpward/>}>Parent folder</Button><Button variant="contained" size="small" disabled={browseStatus!=="available"} onClick={()=>setRoot({...root,path:browsePath||root.path})}>Select this folder</Button></Stack>
          <Paper variant="outlined" sx={{maxHeight:230,overflow:"auto"}}>{browseEntries.filter(e=>e.kind==="directory").map((entry,i)=><Button key={entry.path+i} fullWidth sx={{justifyContent:"space-between",borderRadius:0,borderBottom:"1px solid",borderColor:"divider"}} disabled={entry.selectable===false} onClick={()=>void run(()=>loadBrowse(entry.path,browseRoot))}><span>{entry.name}</span><Chip size="small" variant="outlined" label={entry.status||"Folder"}/></Button>)}{!browseEntries.length&&<Typography sx={{p:2}} color="text.secondary">No visible folders in this location.</Typography>}{browseCursor&&<Button fullWidth onClick={()=>void run(()=>loadBrowse(browsePath,browseRoot,browseCursor||undefined,true))}>Load more folders</Button>}</Paper>
          <Divider/>
          <Box component="form" id="source-create-form" onSubmit={e=>void run(()=>saveSource(e))} sx={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:1.5}}>
            <FormControl size="small"><InputLabel>Location type</InputLabel><Select inputProps={{"aria-label":'Location type'}} label="Location type" value={locationKind} onChange={e=>setLocationKind(e.target.value)}><MenuItem value="local">Local folder</MenuItem><MenuItem value="mounted">External drive or mounted share</MenuItem></Select></FormControl><TextField label="Optional source name" value={sourceLabel} onChange={(e:any)=>setSourceLabel(e.target.value)} inputProps={{maxLength:200}}/>
            <FormControl><InputLabel>Schedule</InputLabel><Select inputProps={{"aria-label":'Schedule'}} label="Schedule" value={schedule} onChange={(e:any)=>setSchedule(Number(e.target.value))}><MenuItem value={0}>Use global schedule</MenuItem><MenuItem value={3600}>Hourly</MenuItem><MenuItem value={21600}>Every 6 hours</MenuItem><MenuItem value={86400}>Every 24 hours</MenuItem><MenuItem value={604800}>Weekly</MenuItem></Select></FormControl>
            <TextField label="Exclusions, one relative path per line" multiline minRows={2} value={exclusions} onChange={(e:any)=>setExclusions(e.target.value)} inputProps={{maxLength:4096}} sx={{gridColumn:"1 / -1"}}/>
          </Box>
        </Stack>}
      </DialogContent>
      {root&&<DialogActions><Button onClick={()=>setAddOpen(false)}>Cancel</Button><Button variant="contained" disabled={busy||browseStatus!=="available"} onClick={e=>{const form=document.getElementById("source-create-form") as HTMLFormElement|null; form?.requestSubmit();}}>Add source</Button></DialogActions>}
    </Dialog>
    <Snackbar open={Boolean(notice)} autoHideDuration={7000} onClose={()=>{setNotice("");setAddedSourceId("")}} message={notice} action={addedSourceId?<Button color="inherit" onClick={()=>void run(()=>startScan(addedSourceId))}>Scan now</Button>:undefined}/>
  </ThemeProvider>;
}

const PageIntro = PageHeader;
function Surface({children,sx}:{children:React.ReactNode;sx?:any}) { return <Paper variant="outlined" sx={{borderRadius:"14px",p:2.5,minWidth:0,borderColor:"divider",...sx}}>{children}</Paper>; }
function StorageGate({created,kind,onClick}:{created?:boolean;kind:"scan"|"vault";onClick:()=>void}) { return <Surface sx={{py:4,px:3,maxWidth:720,mx:"auto",my:4}}><Stack spacing={1.5} alignItems="flex-start"><Lock color="primary"/><Typography variant="h2">{kind==="scan"?(created?"Scan storage is locked":"Set up encrypted scan storage"):"Credential vault is locked"}</Typography><Typography color="text.secondary">{kind==="scan"?"Sources, scan jobs and findings are available after scan storage is unlocked. The credential vault remains independent.":"Credential vault access has its own passphrase and does not affect scan storage."}</Typography>{kind==="scan"&&!created&&window.buddyDesktop&&<Typography color="text.secondary">This desktop workspace is separate from your existing LeakGuard installation. You can explicitly restore a credential backup here.</Typography>}<Button variant="contained" onClick={onClick}>{created?"Unlock scan storage":"Create scan storage"}</Button></Stack></Surface>; }
function Overview({sources,jobs,status,locked,scanDisabled,onUnlock,onSources,onAdd,onScan,onJobAction}:{sources:Source[];jobs:Job[];status:any;locked:boolean;scanDisabled:boolean;onUnlock:()=>void;onSources:()=>void;onAdd:()=>void;onScan:(id:string)=>void;onJobAction:(j:Job,a:"pause"|"resume"|"cancel")=>void}) {
 const active=jobs.filter(activeJob).length;
 const latest=[...jobs].sort((a,b)=>String(b.updated_at||"").localeCompare(String(a.updated_at||""))).slice(0,3);
 const inventory=status.host?.machine_inventory;
 return <><PageIntro eyebrow="WORKSPACE / OVERVIEW" title="Overview" text="A clear view of configured locations, recorded inspections and what still needs attention." action={<Button variant="outlined" startIcon={<Add/>} onClick={sources.length?onSources:onAdd}>{sources.length?"Manage sources":"Add source"}</Button>}/>
 {locked?<StorageGate created={status?.observations?.created} kind="scan" onClick={onUnlock}/>:<>
 {status.host?.protection_paused&&<Alert severity="info" sx={{mb:2.5}}>Automatic protection is paused. Recorded evidence is retained.</Alert>}
 {jobs.some(j=>j.coverage==="incomplete")&&<Alert severity="info" sx={{mb:2.5}}>Initial inventory and content inspection progress separately. Some recorded source coverage is incomplete.</Alert>}
 <Box sx={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:2.5,mb:2.5}}><EvidenceMetric label="Content pending" value={typeof inventory?.pending==="number"?inventory.pending:null} text="Pending versions in the durable inventory."/><EvidenceMetric label="Inspected versions" value={typeof inventory?.inspected==="number"?inventory.inspected:null} text="Configured inspection finished without omissions."/><EvidenceMetric label="Configured sources" value={sources.length} text={active+" queued, running or retrying jobs."}/></Box>
 <Box sx={{display:"grid",gridTemplateColumns:"minmax(0,1fr)","@media (min-width:1400px)":{gridTemplateColumns:"minmax(0,1.8fr) minmax(280px,1fr)"},gap:2.5,alignItems:"start"}}>
 <Stack spacing={2.5}><Box><SectionTitle title="Locations" action={<Button onClick={onSources}>Manage</Button>}/>{sources.length===0?<EmptyState title="No additional locations" text="Automatic local coverage and explicitly added locations appear here after discovery." action={<Button variant="contained" onClick={onAdd}>Add source</Button>}/>:<SourceTable sources={sources} jobs={jobs} onSelect={onSources} scanDisabled={scanDisabled} onScan={s=>onScan(s.id)}/>}</Box><Box><SectionTitle title="Recent scan activity"/>{latest.length===0?<EmptyState title="No recorded scan jobs" text="Activity appears when a configured location is inspected."/>:<JobList jobs={latest} sources={sources} scanDisabled={scanDisabled} onAction={onJobAction}/>}</Box></Stack>
 <InspectionHealth value={status.host?.inspection_evidence}/>
 </Box>
 </>}
 </>;
}
function SectionTitle({title,action}:{title:string;action?:React.ReactNode}) { return <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{mt:3,mb:1}}><Typography variant="h3">{title}</Typography>{action}</Stack>; }
function EmptyState({title,text,action}:{title:string;text:string;action?:React.ReactNode}) { return <Surface sx={{py:3}}><Typography fontWeight={600}>{title}</Typography><Typography color="text.secondary" sx={{mt:.5,mb:action?2:0}}>{text}</Typography>{action}</Surface>; }
function SourceTable({sources,jobs=[],selected,scanDisabled,onSelect,onScan}:{sources:Source[];jobs?:Job[];selected?:string;scanDisabled?:boolean;onSelect?:(s:Source)=>void;onScan:(s:Source)=>void}) {
 return <Surface sx={{p:0,overflow:"hidden"}}>{sources.length===0?<Typography sx={{p:2}} color="text.secondary">No sources have been added.</Typography>:<Box sx={{overflowX:"auto"}}><table className="workbench-table"><thead><tr>{["Source","Job state","Coverage","Last completed source job","Schedule",""].map(x=><th key={x} className={x==="Last completed source job"?"source-extra":undefined} style={{textAlign:"left",padding:"12px 14px",borderBottom:"1px solid var(--mui-palette-divider)",color:"var(--mui-palette-text-secondary)",fontWeight:600}}>{x}</th>)}</tr></thead><tbody>{sources.map(s=>{const job=jobs.filter(j=>j.source_id===s.id).sort((a,b)=>String(b.updated_at||"").localeCompare(String(a.updated_at||"")))[0]; const state=jobStateLabel(job?.state); const coverage=job?.coverage?coverageText(job.coverage):"Unknown"; const scheduleLabel=(s.enabled===false?"Disabled · ":"")+sourceScheduleText(s); return <tr key={s.id} tabIndex={onSelect?0:undefined} onKeyDown={e=>{if(onSelect&&e.target===e.currentTarget&&(e.key==="Enter"||e.key===" ")){e.preventDefault();onSelect(s)}}} onClick={()=>onSelect?.(s)} aria-selected={selected===s.id} style={{cursor:onSelect?"pointer":"default",background:selected===s.id?"var(--mui-palette-action-selected)":undefined}}><td style={{padding:14,borderBottom:"1px solid var(--mui-palette-divider)"}}><b>{s.label||s.root}</b><div className="path-text" style={{fontSize:12,color:"var(--mui-palette-text-secondary)",marginTop:4}}>{s.root}</div>{s.availability&&<Chip sx={{mt:.75}} size="small" variant="outlined" color={["offline","source-unavailable","permission-denied","identity-changed"].includes(s.availability)?"warning":"default"} label={availabilityText(s.availability)}/>}</td><td style={{padding:14,borderBottom:"1px solid var(--mui-palette-divider)"}}>{state}</td><td style={{padding:14,borderBottom:"1px solid var(--mui-palette-divider)"}}>{coverage}</td><td className="source-extra" style={{padding:14,borderBottom:"1px solid var(--mui-palette-divider)"}}>{dateText(s.last_success_at)}</td><td style={{padding:14,borderBottom:"1px solid var(--mui-palette-divider)"}}>{scheduleLabel}</td><td style={{padding:14,borderBottom:"1px solid var(--mui-palette-divider)"}}><Button size="small" disabled={scanDisabled} onClick={e=>{e.stopPropagation();onScan(s);}}>Scan now</Button></td></tr>})}</tbody></table></Box>}</Surface>;
}
function SourceInspector({source,jobs=[],scanDisabled,onSchedule,onScan,onEnable,onRemove}:{source?:Source;jobs?:Job[];scanDisabled?:boolean;onSchedule:(s:Source,v:number)=>void;onScan:(s:Source)=>void;onEnable:(s:Source)=>void;onRemove:(s:Source)=>void}) {
 const [schedule,setSchedule]=useState(0);
 useEffect(()=>setSchedule(sourceScheduleSeconds(source)),[source?.id,source?.schedule_seconds,source?.schedule?.mode,source?.schedule?.interval_seconds,source?.schedule?.daily_time,source?.schedule?.timezone]);
 if(!source) return <Surface><Typography fontWeight={600}>Select a source</Typography><Typography variant="body2" color="text.secondary">Choose a source row to inspect its scope and settings.</Typography></Surface>;
 const latestJob=jobs.filter(j=>j.source_id===source.id).sort((a,b)=>String(b.updated_at||"").localeCompare(String(a.updated_at||"")))[0]; return <Surface><Typography variant="h3">{source.label||"Source details"}</Typography><Typography className="path-text" variant="body2" sx={{my:1,overflowWrap:"anywhere"}}>{source.root}</Typography><Divider sx={{my:1.5}}/><Typography variant="caption" color="text.secondary">Source kind</Typography><Typography>{source.kind||"local"}</Typography><Typography variant="caption" color="text.secondary" display="block" sx={{mt:1}}>Availability</Typography><Typography>{availabilityText(source.availability)}</Typography>{latestJob?.last_error&&<Alert severity="warning" sx={{my:1.5}}>{apiMessages[latestJob.last_error]||"This source needs attention."} Reconnect or review access, then scan again. Details: {latestJob.last_error}</Alert>}<Typography variant="caption" color="text.secondary" display="block" sx={{mt:1}}>Latest coverage</Typography><Typography>{latestJob?.coverage?coverageText(latestJob.coverage):"Unknown"}</Typography><Typography variant="caption" color="text.secondary">{jobStateLabel(latestJob?.state)}</Typography><Typography variant="caption" color="text.secondary" display="block" sx={{mt:1}}>Last completed source job</Typography><Typography>{dateText(source.last_success_at)}</Typography><Typography variant="caption" color="text.secondary" display="block" sx={{mt:1}}>Schedule</Typography><Typography>{sourceScheduleText(source)}</Typography><FormControl size="small" fullWidth sx={{mt:1}}><InputLabel>Scan schedule</InputLabel><Select inputProps={{"aria-label":'Scan schedule'}} label="Scan schedule" value={schedule} onChange={e=>setSchedule(Number(e.target.value))}>{source.schedule?.mode==="daily"&&<MenuItem value={-1}>{sourceScheduleText(source)}</MenuItem>}{schedule>0&&![3600,21600,86400,604800].includes(schedule)&&<MenuItem value={schedule}>{scheduleText(schedule)}</MenuItem>}<MenuItem value={0}>Use global schedule</MenuItem><MenuItem value={3600}>Hourly</MenuItem><MenuItem value={21600}>Every 6 hours</MenuItem><MenuItem value={86400}>Every 24 hours</MenuItem><MenuItem value={604800}>Weekly</MenuItem></Select></FormControl><Button size="small" disabled={schedule<0} onClick={()=>onSchedule(source,schedule)}>Save schedule</Button>{source.schedule?.mode==="daily"&&<Typography variant="caption" sx={{display:"block"}}>Change the daily time and time zone in Settings.</Typography>}<Typography variant="caption" color="text.secondary" display="block" sx={{mt:1}}>Exclusions</Typography><Typography variant="body2">{(source.exclusions||[]).length?(source.exclusions||[]).join(", "):"None"}</Typography><Stack spacing={1} sx={{mt:2}}><Button variant="contained" disabled={scanDisabled} onClick={()=>onScan(source)}>Scan now</Button><Button variant="outlined" onClick={()=>onEnable(source)}>{source.enabled===false?"Enable source":"Disable source"}</Button><Button color="error" onClick={()=>onRemove(source)}>Remove source</Button></Stack></Surface>;
}
function JobList({jobs,sources,scanDisabled,onAction}:{jobs:Job[];sources:Source[];scanDisabled?:boolean;onAction:(j:Job,a:"pause"|"resume"|"cancel")=>void}) {
 if (!jobs.length) return <EmptyState title="No scan jobs yet" text="Scan activity appears here after you choose Scan now." />;
 return <Stack spacing={1}>{jobs.map(job=>{const source=sources.find(s=>s.id===job.source_id); return <Surface key={job.id}><Stack direction="row" justifyContent="space-between" alignItems="center" gap={2} sx={{flexWrap:"wrap"}}><Box><Typography fontWeight={600}>{source?.label||source?.root||"Scan job"}</Typography><Typography variant="body2" color="text.secondary">{job.state==="completed"?(job.coverage==="complete"?(source?.managed_inventory?"Backfill finished":"Job finished · coverage complete"):"Job finished · coverage incomplete"):jobStateLabel(job.state)}  {job.files_scanned==null?"Files checked: Not measured":job.files_scanned+" files checked"}{job.pending_files==null?"":"  "+job.pending_files+" pending"}  {coverageText(job.coverage)}</Typography>{job.last_error&&<Typography variant="caption" color="error.main">{apiMessages[job.last_error]||"Scan issue"} Details: {job.last_error}</Typography>}<Typography variant="caption" color="text.secondary" display="block" sx={{mt:.75}}>Stage progress: Not measured · Updated: {dateText(job.updated_at)}</Typography></Box><Stack direction="row">{["queued","running"].includes(job.state)&&<Button onClick={()=>onAction(job,"pause")} startIcon={<Pause/>}>Pause</Button>}{["paused","backoff"].includes(job.state)&&source?.enabled!==false&&<Button disabled={scanDisabled} onClick={()=>onAction(job,"resume")} startIcon={<PlayArrow/>}>Resume</Button>}{["paused","backoff"].includes(job.state)&&source?.enabled===false&&<Chip size="small" label="Enable source before resuming" variant="outlined"/>}{["queued","running","paused","backoff"].includes(job.state)&&<Button color="error" onClick={()=>onAction(job,"cancel")} startIcon={<Stop/>}>Cancel</Button>}</Stack></Stack></Surface>})}</Stack>;
}
function GitPlaceholder() {
 const [repository,setRepository]=useState(""); const [profile,setProfile]=useState("credentials"); const [status,setStatus]=useState<any>(null); const [error,setError]=useState(""); const [busy,setBusy]=useState(false);
 async function run(work:()=>Promise<void>){setBusy(true);setError("");try{await work()}catch(e){setError((e as Error).message)}finally{setBusy(false)}}
 async function check(e?:React.FormEvent){e?.preventDefault();if(!repository.trim())throw new Error("Enter a repository folder.");const params=new URLSearchParams({repository:repository.trim()});const data=await request<any>("/hooks/status?"+params.toString());setStatus(data);setRepository(data.repository||repository);}
 async function choose(){if(!window.buddyDesktop){setError("Native folder picker is unavailable. Enter the repository path manually.");return;}const value=await window.buddyDesktop.chooseDirectory();if(!value.canceled&&value.path)setRepository(value.path);}
 async function install(){if(!status)return;if(!window.confirm("Install Buddy Git guards for this repository using the selected profile?"))return;await request("/hooks/install","POST",{repository:status.repository,profile});await check();}
 async function remove(){if(!status||!window.confirm("Remove Buddy-managed Git guards from this repository?"))return;await request("/hooks/uninstall","POST",{repository:status.repository});await check();}
 return <Stack spacing={2}><Surface><Typography variant="h3">Git guards for one repository</Typography><Typography variant="body2" color="text.secondary" sx={{my:1}}>Check guards explicitly. Choosing a folder does not prove it is a Git repository.</Typography><Box component="form" onSubmit={e=>void run(()=>check(e))} sx={{display:"grid",gridTemplateColumns:"minmax(220px,1fr) auto minmax(190px,220px) auto",gap:1,alignItems:"center"}}><TextField label="Repository folder" value={repository} onChange={(e:any)=>setRepository(e.target.value)} required slotProps={{htmlInput:{maxLength:4096}}}/><Button variant="outlined" onClick={()=>void choose()}>Choose folder</Button><FormControl size="small"><InputLabel>Profile</InputLabel><Select value={profile} inputProps={{"aria-label":'Profile'}} label="Profile" onChange={e=>setProfile(e.target.value)}><MenuItem value="credentials">Credentials</MenuItem><MenuItem value="sensitive">Sensitive information</MenuItem><MenuItem value="firm">Firm</MenuItem></Select></FormControl><Button variant="contained" type="submit" disabled={busy}>Check guards</Button></Box>{error&&<Alert severity="error" sx={{mt:2}}>{error}</Alert>}</Surface>
 {status&&<Surface><Typography variant="h3">{status.repository||"Selected repository"}</Typography><Typography variant="body2" sx={{my:1}}>{status.managed?.length?"Managed hooks: "+status.managed.join(", "):"No Buddy-managed hooks are installed here."}</Typography>{status.managed?.length>0&&<><Typography variant="body2">Installed snapshot: {status.profile||"Unknown"} profile / worker policy {status.worker_policy||"Unknown"}</Typography><Typography variant="caption" display="block" className="path-text">Effective config: {status.effective_config_path||"Not recorded"}</Typography></>}<Typography variant="caption" display="block" color="text.secondary" sx={{mt:1}}>A new profile setting does not change an already installed hook snapshot.</Typography><Stack direction="row" spacing={1} sx={{mt:2}}>{status.managed?.length>0?<Button color="error" onClick={()=>void run(remove)}>Remove guards</Button>:<Button variant="contained" onClick={()=>void run(install)}>Install guards</Button>}</Stack></Surface>}</Stack>;
}
function SecondaryScreen({page,status,onRefresh}:{page:string;status:any;onRefresh:()=>void}) { return <><PageIntro eyebrow={page==="vault"?"ENCRYPTED LOCAL STORAGE":"LOCAL WORKSPACE"} title={pageTitle[page as Page]} text="This view is loading its live service state." action={<Button startIcon={<Refresh/>} onClick={onRefresh}>Refresh</Button>}/><Alert severity="info">Workspace data is not available until its API view is connected.</Alert></>; }
