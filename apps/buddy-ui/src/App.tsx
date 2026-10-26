import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Alert, AppBar, Box, Button, Chip, CircularProgress, CssBaseline, Dialog, DialogActions, DialogContent, DialogTitle,
  Divider, Drawer, FormControl, FormControlLabel, IconButton, InputLabel, LinearProgress, MenuItem, Paper, Select,
  Snackbar, Stack as MuiStack, Switch, Tab, Tabs, TextField as MuiTextField, ThemeProvider, Toolbar, Typography as MuiTypography, createTheme
} from "@mui/material";
import { Add, Key, Lock, FolderOpen, Dashboard, Search, VpnKey, Extension, Settings as SettingsIcon, Refresh, Close, ChevronRight, ArrowUpward, PlayArrow, Pause, Stop, DeleteOutlined, Tune } from "@mui/icons-material";
import { AgGridReact } from "ag-grid-react";
import { AllCommunityModule, ModuleRegistry, themeQuartz } from "ag-grid-community";
import { initializeSession, request, setConnectionHandlers } from "./api";
const Stack: any = ({ alignItems, justifyContent, gap, ...props }: any) => <MuiStack {...props} sx={{ alignItems, justifyContent, gap, ...props.sx }} />;
const Typography: any = ({ fontWeight, fontSize, display, ...props }: any) => <MuiTypography {...props} sx={{ fontWeight, fontSize, display, ...props.sx }} />;
const TextField: any = ({ inputProps, ...props }: any) => <MuiTextField {...props} slotProps={{ ...(props.slotProps || {}), htmlInput: inputProps }} />;
ModuleRegistry.registerModules([AllCommunityModule]);

type Page = "overview" | "sources" | "findings" | "vault" | "plugins" | "settings";
type Source = { id: string; label?: string; root: string; kind?: string; enabled?: boolean; schedule_seconds?: number | null; last_success_at?: string | null; exclusions?: string[] };
type Job = { id: string; source_id: string; state: string; files_scanned?: number; pending_files?: number | null; coverage?: string; last_error?: string; updated_at?: string };
type Root = { name?: string; path: string; kind?: string; status?: string; selectable?: boolean };
const nav: { id: Page; label: string; icon: React.ReactNode }[] = [
  { id: "overview", label: "Overview", icon: <Dashboard fontSize="small" /> }, { id: "sources", label: "Sources", icon: <FolderOpen fontSize="small" /> },
  { id: "findings", label: "Findings", icon: <Search fontSize="small" /> }, { id: "vault", label: "Credential vault", icon: <VpnKey fontSize="small" /> },
  { id: "plugins", label: "Plugins", icon: <Extension fontSize="small" /> }, { id: "settings", label: "Settings", icon: <SettingsIcon fontSize="small" /> }
];
const colors = {
 light: { canvas:"#F5F7F9", surface:"#FFFFFF", subtle:"#EDF1F4", text:"#172B4D", muted:"#596779", border:"#DCE3EB", accent:"#087F8C", accentHover:"#066875", accentTint:"#E7F4F4", danger:"#B42318", warning:"#8B6000", success:"#23734C", focus:"#087F8C" },
 dark: { canvas:"#151C25", surface:"#1D2733", subtle:"#263442", text:"#E5EDF5", muted:"#A8B8C9", border:"#3B4B5C", accent:"#61CCD0", accentHover:"#84E0E3", accentTint:"#193D42", danger:"#FFB4AA", warning:"#F3CE76", success:"#91D8AE", focus:"#61CCD0" }
};
const pageTitle: Record<Page,string> = { overview:"Overview", sources:"Sources", findings:"Findings", vault:"Credential vault", plugins:"Plugins", settings:"Settings" };
const activeJob = (job: Job) => ["queued","running","backoff"].includes(job.state);
const dateText = (value?: string | null) => value ? new Date(value).toLocaleString() : "Not yet checked";
const coverageText = (value?: string | null) => value === "complete" ? "Complete" : value === "incomplete" ? "Incomplete" : value || "Not yet checked";
const scheduleText = (value?: number | null) => !value ? "Manual" : value === 3600 ? "Hourly" : value === 21600 ? "Every 6 hours" : value === 86400 ? "Daily" : value === 604800 ? "Weekly" : "Every " + Math.round(value / 60) + " minutes";

export default function App() {
  const [appearance, setAppearance] = useState<"system"|"light"|"dark">("system");
  const [page, setPage] = useState<Page>((location.hash.slice(1) as Page) || "overview");
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
  const [error, setError] = useState("");
  const [addOpen, setAddOpen] = useState(false);
  const [roots, setRoots] = useState<Root[]>([]);
  const [root, setRoot] = useState<Root | null>(null);
  const [browsePath, setBrowsePath] = useState("");
  const [browseEntries, setBrowseEntries] = useState<any[]>([]);
  const [browseCursor, setBrowseCursor] = useState<string | null>(null);
  const [browseRoot, setBrowseRoot] = useState("");
  const [sourceLabel, setSourceLabel] = useState("");
  const [schedule, setSchedule] = useState(0);
  const [exclusions, setExclusions] = useState("");
  const [manualRoot, setManualRoot] = useState("");
  const [gateOpen, setGateOpen] = useState(false);
  const [gateTarget, setGateTarget] = useState<"observations"|"observations-create">("observations");
  const [passphrase, setPassphrase] = useState("");
  const [passphraseConfirm, setPassphraseConfirm] = useState("");
  const [themeMode, setThemeMode] = useState<"light"|"dark">("light");
  const [mobileDrawer, setMobileDrawer] = useState(false);
  const revealGeneration = useRef(0);

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
    palette: { mode: themeMode, primary: { main: palette.accent, dark: palette.accentHover, contrastText: themeMode === "dark" ? "#10262A" : "#FFFFFF" }, background: { default: palette.canvas, paper: palette.surface }, text: { primary: palette.text, secondary: palette.muted }, divider: palette.border, error:{main:palette.danger}, warning:{main:palette.warning}, success:{main:palette.success} },
    typography: { fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif', fontSize: 14, h1:{fontSize:24,lineHeight:"32px",fontWeight:600}, h2:{fontSize:18,lineHeight:"26px",fontWeight:600}, h3:{fontSize:16,lineHeight:"24px",fontWeight:600}, body2:{fontSize:13,lineHeight:"20px"} },
    shape: { borderRadius: 6 }, components: { MuiButton:{styleOverrides:{root:{height:36,textTransform:"none",fontWeight:600}}}, MuiOutlinedInput:{styleOverrides:{root:{minHeight:36}}}, MuiPaper:{styleOverrides:{root:{backgroundImage:"none"}}}, MuiCssBaseline:{styleOverrides:{"*":{boxSizing:"border-box"},"::selection":{backgroundColor:palette.accentTint}}}}
  }), [themeMode,palette]);
  const refreshStatus = useCallback(async () => {
    const data = await request<any>("/status");
    setStatus(data); setConnected(true);
    const observation = data.observations || {};
    if (observation.unlocked) {
      const [ss, jj] = await Promise.all([request<any>("/sources"), request<any>("/jobs")]);
      setSources(Array.isArray(ss) ? ss : ss.sources || []);
      setJobs(Array.isArray(jj) ? jj : jj.jobs || []);
    } else { setSources([]); setJobs([]); setSelectedSource(""); }
  }, []);
  const refreshAll = useCallback(async () => {
    try { await refreshStatus(); setError(""); }
    catch (e) { setConnected(false); setError((e as Error).message || "Password Buddy is unavailable."); }
  }, [refreshStatus]);
  useEffect(() => {
    let alive = true;
    initializeSession().then(() => { if (alive) { setSessionReady(true); setSessionError(""); } }).catch(e => { if (alive) setSessionError((e as Error).message); });
    setConnectionHandlers(() => { setConnected(false); setError("Backend connection unavailable. Retry to refresh live data."); scrubSensitive(); }, () => setConnected(true));
    return () => { alive = false; };
  }, []);
  useEffect(() => { if (sessionReady) void refreshAll(); }, [sessionReady, refreshAll]);
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
    const fn = () => { const value = location.hash.slice(1) as Page; if (nav.some(n=>n.id===value)) setPage(value); };
    window.addEventListener("hashchange", fn);
    const off = window.buddyDesktop?.onEvent(event => {
      if (event.type === "navigate") navigate(event.page);
      if (event.type === "clear-sensitive" || event.type === "vault-locked") scrubSensitive();
      if (event.type === "backend-state" && event.state !== "ready") { scrubSensitive(); setConnected(false); setError("Backend connection unavailable. Retry to refresh live data."); }
    });
    const blur = () => { if (document.activeElement instanceof HTMLElement) document.activeElement.blur(); scrubSensitive(); };
    window.addEventListener("blur", blur);
    return () => { window.removeEventListener("hashchange", fn); window.removeEventListener("blur", blur); off?.(); };
  }, []);
  function scrubSensitive() { revealGeneration.current++; setPassphrase(""); setPassphraseConfirm(""); }
  function navigate(next: Page) { scrubSensitive(); setPage(next); setMobileDrawer(false); history.replaceState(null,"","#"+next); if (next==="sources") setSourceTab(0); }
  async function run(action: () => Promise<void>) { setBusy(true); setError(""); try { await action(); } catch (e) { setError((e as Error).message || "Request failed."); } finally { setBusy(false); } }
  function openGate(target: "observations"|"observations-create") { setGateTarget(target); setPassphrase(""); setPassphraseConfirm(""); setGateOpen(true); }
  async function submitGate() {
    if (gateTarget === "observations-create" && passphrase !== passphraseConfirm) throw new Error("Passphrases do not match.");
    if (passphrase.length < 12) throw new Error("Passphrases must contain at least 12 characters.");
    await request("/observations/" + (gateTarget === "observations-create" ? "create" : "unlock"), "POST", {passphrase});
    setPassphrase(""); setPassphraseConfirm(""); setGateOpen(false); await refreshAll();
    setNotice(gateTarget === "observations-create" ? "Encrypted scan storage created." : "Scan storage unlocked.");
  }
  async function openAddSource() {
    setAddOpen(true); setRoot(null); setBrowsePath(""); setBrowseEntries([]); setBrowseCursor(null); setSourceLabel(""); setSchedule(0); setExclusions("");
    const list = await request<any>("/roots"); setRoots(Array.isArray(list) ? list : list.roots || []);
  }
  async function loadBrowse(path: string, rootPath: string, cursor?: string, append = false) {
    const q = new URLSearchParams({path, root:rootPath}); if (cursor) q.set("cursor",cursor);
    const result = await request<any>("/browse?" + q.toString());
    setBrowsePath(result.path || path); setBrowseRoot(rootPath);
    setBrowseEntries(append ? old => [...old, ...(result.entries || [])] : result.entries || []);
    setBrowseCursor(result.next_cursor || null);
    if (!root) setRoot({path:rootPath,kind:rootPath.startsWith("\\\\") ? "unc" : "local"});
  }
  async function chooseRoot(path: string, kind = "local") {
    setRoot({path,kind}); setBrowseRoot(path);
    await loadBrowse(path,path);
  }
  async function saveSource(e: React.FormEvent) {
    e.preventDefault(); if (!root) throw new Error("Select a source folder first.");
    const relativeExclusions = exclusions.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
    if (relativeExclusions.length > 100) throw new Error("Use at most 100 exclusion paths.");
    const payload: any = {root:root.path, kind:root.kind, exclusions:relativeExclusions};
    if (sourceLabel.trim()) payload.label = sourceLabel.trim();
    if (schedule > 0) payload.schedule_seconds = schedule;
    await request("/sources","POST",payload);
    setAddOpen(false); await refreshAll(); setNotice("Source added. Start a scan when you are ready.");
  }
  async function startScan(id: string) { await request("/scans","POST",{source_id:id}); await refreshAll(); setNotice("Scan queued."); }
  async function setSourceEnabled(s: Source) { await request("/sources/"+encodeURIComponent(s.id),"PATCH",{enabled:s.enabled===false}); await refreshAll(); }
  async function removeSource(s: Source) { if (!window.confirm("Remove this source and its schedule? Scan history is retained.")) return; await request("/sources/"+encodeURIComponent(s.id),"DELETE",{}); setSelectedSource(""); await refreshAll(); }
  async function jobAction(job: Job, action: "pause"|"resume"|"cancel") { await request("/jobs/"+encodeURIComponent(job.id)+"/"+action,"POST",{}); await refreshAll(); }
  const selected = sources.find(s=>s.id===selectedSource) || sources[0];
  const unreadableStatus = !sessionReady ? "" : sessionError || (!connected && !error ? "Connecting to Password Buddzyy" : "");
  const scanGate = status?.observations?.unlocked !== true;
  const sourceRows = sources;
  const drawer = <Box sx={{width:208,height:"100%",display:"flex",flexDirection:"column",bgcolor:"background.paper",borderRight:"1px solid",borderColor:"divider"}}>
    <Box sx={{px:2.5,py:2.3,display:"flex",alignItems:"center",gap:1.25}}><Box sx={{width:30,height:30,borderRadius:1.5,bgcolor:"primary.main",color:"primary.contrastText",display:"grid",placeItems:"center"}}><Key fontSize="small"/></Box><Box><Typography fontWeight={700} fontSize={14}>Password Buddy</Typography><Typography variant="caption" color="text.secondary">LeakGuard engine</Typography></Box></Box>
    <Divider/>
    <Box component="nav" aria-label="Main navigation" sx={{p:1.25,display:"grid",gap:.5}}>{nav.map(item=><Button key={item.id} onClick={()=>navigate(item.id)} startIcon={item.icon} fullWidth sx={{justifyContent:"flex-start",height:38,color:page===item.id?"primary.main":"text.secondary",bgcolor:page===item.id?"action.selected":"transparent"}}>{item.label}</Button>)}</Box>
    <Box sx={{mt:"auto",p:2,borderTop:"1px solid",borderColor:"divider"}}><Typography variant="caption" color="text.secondary">Private to this device</Typography><Typography variant="caption" display="block" color={connected?"success.main":"text.secondary"}>{connected?"Loopback connection":"Connection unavailable"}</Typography></Box>
  </Box>;

  if (!sessionReady && !sessionError) return <ThemeProvider theme={muiTheme}><CssBaseline/><Box sx={{height:"100vh",display:"grid",placeItems:"center"}}><Stack alignItems="center" spacing={2}><CircularProgress/><Typography>Opening Password Buddy</Typography></Stack></Box></ThemeProvider>;

  return <ThemeProvider theme={muiTheme}><CssBaseline/>
    <Box sx={{display:"flex",minHeight:"100vh",bgcolor:"background.default"}}>
      <Box sx={{display:{xs:"none",lg:"block"}}}>{drawer}</Box>
      <Drawer open={mobileDrawer} onClose={()=>setMobileDrawer(false)}>{drawer}</Drawer>
      <Box sx={{flex:1,minWidth:0}}>
        <AppBar position="sticky" color="inherit" elevation={0} sx={{borderBottom:"1px solid",borderColor:"divider",bgcolor:"background.paper"}}>
          <Toolbar sx={{minHeight:"56px !important",px:"32px !important",gap:2}}><IconButton onClick={()=>setMobileDrawer(true)} sx={{display:{lg:"none"}}} aria-label="Open navigation"><Tune/></IconButton><Typography variant="h1" sx={{fontSize:20,flex:1}}>{pageTitle[page] || "Overview"}</Typography><Chip size="small" label={connected?"Connected":"Unavailable"} color={connected?"success":"default"} variant="outlined"/><IconButton aria-label="Refresh" onClick={()=>void refreshAll()}><Refresh/></IconButton></Toolbar>
        </AppBar>
        <Box component="main" sx={{p:"28px 32px 40px",maxWidth:1540,mx:"auto"}}>
          {unreadableStatus && <Alert severity={sessionError?"error":"info"} sx={{mb:2}} action={sessionError ? undefined : <Button onClick={()=>void refreshAll()}>Retry</Button>}>{unreadableStatus}</Alert>}
          {error && <Alert severity="error" sx={{mb:2}} onClose={()=>setError("")}>{error}</Alert>}
          {!sessionError && page==="overview" && <Overview sources={sourceRows} jobs={jobs} status={status} locked={scanGate} onUnlock={()=>openGate(status?.observations?.created?"observations":"observations-create")} onSources={()=>navigate("sources")} onAdd={()=>void run(openAddSource)} onScan={id=>void run(()=>startScan(id))}/>}
          {!sessionError && page==="sources" && <>
            <PageIntro eyebrow="LOCAL FOLDERS AND SHARES" title="Sources" text="Choose folders and shares, then review scan coverage and activity." action={<Button variant="contained" startIcon={<Add/>} onClick={()=>void run(openAddSource)}>Add source</Button>}/>
            {scanGate ? <StorageGate created={status?.observations?.created} kind="scan" onClick={()=>openGate(status?.observations?.created?"observations":"observations-create")}/> : <>
              <Tabs value={sourceTab} onChange={(_,v)=>setSourceTab(v)} sx={{mb:2}}><Tab label="Sources"/><Tab label="Scan activity"/><Tab label="Git guards"/></Tabs>
              {sourceTab===0 && <Box sx={{display:"grid",gridTemplateColumns:"minmax(0,1fr) 300px",gap:2,alignItems:"start"}}>
                <SourceTable sources={sources} selected={selected?.id} onSelect={s=>setSelectedSource(s.id)} onScan={s=>void run(()=>startScan(s.id))}/>
                <SourceInspector source={selected} onScan={s=>void run(()=>startScan(s.id))} onEnable={s=>void run(()=>setSourceEnabled(s))} onRemove={s=>void run(()=>removeSource(s))}/>
              </Box>}
              {sourceTab===1 && <JobList jobs={jobs} sources={sources} onAction={(j,a)=>void run(()=>jobAction(j,a))}/>}
              {sourceTab===2 && <GitPlaceholder/>}
            </>}
          </>}
          {!sessionError && ["findings","vault","plugins","settings"].includes(page) && <SecondaryScreen page={page} status={status} onRefresh={()=>void refreshAll()} />}
        </Box>
      </Box>
    </Box>
    <Dialog open={gateOpen} onClose={()=>{setGateOpen(false);setPassphrase("");setPassphraseConfirm("");}} fullWidth maxWidth="xs">
      <DialogTitle>{gateTarget==="observations-create"?"Create encrypted scan storage":"Unlock scan storage"}</DialogTitle>
      <DialogContent><Stack spacing={2} sx={{pt:1}}><Typography variant="body2">{gateTarget==="observations-create"?"Scan history and review notes are encrypted separately from the credential vault.":"Unlock the observation store to browse sources, jobs and findings."}</Typography><TextField type="password" label="Passphrase" value={passphrase} onChange={(e:any)=>setPassphrase(e.target.value)} inputProps={{maxLength:1024,autoComplete:"new-password"}} autoFocus/><Typography variant="caption" color="text.secondary">{gateTarget==="observations-create"?"Use 12yy1024 characters.":"Passphrase is held only for this action."}</Typography>{gateTarget==="observations-create"&&<TextField type="password" label="Confirm passphrase" value={passphraseConfirm} onChange={(e:any)=>setPassphraseConfirm(e.target.value)} inputProps={{maxLength:1024,autoComplete:"new-password"}}/>}</Stack></DialogContent>
      <DialogActions><Button onClick={()=>{setPassphrase("");setPassphraseConfirm("");setGateOpen(false);}}>Cancel</Button><Button variant="contained" disabled={busy} onClick={()=>void run(submitGate)}>Continue</Button></DialogActions>
    </Dialog>
    <Dialog open={addOpen} onClose={()=>setAddOpen(false)} fullWidth maxWidth="md">
      <DialogTitle sx={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>Add a source<IconButton aria-label="Close" onClick={()=>setAddOpen(false)}><Close/></IconButton></DialogTitle>
      <DialogContent dividers>
        {!root ? <Stack spacing={2}>
          <Typography variant="body2" color="text.secondary">Choose a common location, or enter a folder path. Buddy will inspect only the selected root.</Typography>
          <Box sx={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(230px,1fr))",gap:1}}>{roots.map((item,i)=><Button key={item.path+i} variant="outlined" disabled={item.selectable===false||["offline","permission-denied","platform-unavailable"].includes(item.status||"")} onClick={()=>void run(()=>chooseRoot(item.path,item.kind||"local"))} sx={{justifyContent:"flex-start",textAlign:"left",p:1.5}}><Stack alignItems="flex-start"><Typography fontWeight={600}>{item.name||item.path}</Typography><Typography variant="caption" className="path-text">{item.status||"Available"}  {item.path}</Typography></Stack></Button>)}</Box>
          <Divider>or enter path</Divider><Stack direction="row" spacing={1}><TextField label="Folder or mounted share" fullWidth value={manualRoot} onChange={(e:any)=>setManualRoot(e.target.value)} inputProps={{maxLength:4096}} placeholder="/path/to/folder or \\\\server\\share"/><Button variant="outlined" onClick={()=>void run(()=>chooseRoot(manualRoot.trim(),manualRoot.trim().startsWith("\\\\")?"unc":"local"))}>Browse</Button></Stack>
        </Stack> : <Stack spacing={2}>
          <Stack direction="row" spacing={1} alignItems="center"><Button size="small" onClick={()=>{setRoot(null);setBrowseEntries([]);}}>Choose another root</Button><Typography variant="body2" className="path-text">{browsePath || root.path}</Typography></Stack>
          <Stack direction="row" spacing={1}><Button variant="outlined" size="small" onClick={()=>void run(()=>{const p=browsePath.replace(/[\\/]+$/,""); const sep=p.includes("\\")?"\\":"/"; const parts=p.split(/[\\/]/); parts.pop(); const parent=parts.join(sep)||sep; return loadBrowse(parent,browseRoot);})} startIcon={<ArrowUpward/>}>Parent folder</Button><Button variant="contained" size="small" onClick={()=>setRoot({...root,path:browsePath||root.path})}>Select this folder</Button></Stack>
          <Paper variant="outlined" sx={{maxHeight:230,overflow:"auto"}}>{browseEntries.filter(e=>e.kind==="directory").map((entry,i)=><Button key={entry.path+i} fullWidth sx={{justifyContent:"space-between",borderRadius:0,borderBottom:"1px solid",borderColor:"divider"}} disabled={entry.selectable===false} onClick={()=>void run(()=>loadBrowse(entry.path,browseRoot))}><span>{entry.name}</span><Chip size="small" variant="outlined" label={entry.status||"Folder"}/></Button>)}{!browseEntries.length&&<Typography sx={{p:2}} color="text.secondary">No visible folders in this location.</Typography>}{browseCursor&&<Button fullWidth onClick={()=>void run(()=>loadBrowse(browsePath,browseRoot,browseCursor||undefined,true))}>Load more folders</Button>}</Paper>
          <Divider/>
          <Box component="form" id="source-create-form" onSubmit={e=>void run(()=>saveSource(e))} sx={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:1.5}}>
            <TextField label="Optional source name" value={sourceLabel} onChange={(e:any)=>setSourceLabel(e.target.value)} inputProps={{maxLength:200}}/>
            <FormControl><InputLabel>Schedule</InputLabel><Select label="Schedule" value={schedule} onChange={(e:any)=>setSchedule(Number(e.target.value))}><MenuItem value={0}>Manual scans only</MenuItem><MenuItem value={3600}>Hourly</MenuItem><MenuItem value={21600}>Every 6 hours</MenuItem><MenuItem value={86400}>Daily</MenuItem><MenuItem value={604800}>Weekly</MenuItem></Select></FormControl>
            <TextField label="Exclusions, one relative path per line" multiline minRows={2} value={exclusions} onChange={(e:any)=>setExclusions(e.target.value)} inputProps={{maxLength:4096}} sx={{gridColumn:"1 / -1"}}/>
          </Box>
        </Stack>}
      </DialogContent>
      {root&&<DialogActions><Button onClick={()=>setAddOpen(false)}>Cancel</Button><Button variant="contained" disabled={busy} onClick={e=>{const form=document.getElementById("source-create-form") as HTMLFormElement|null; form?.requestSubmit();}}>Add source</Button></DialogActions>}
    </Dialog>
    <Snackbar open={Boolean(notice)} autoHideDuration={5000} onClose={()=>setNotice("")} message={notice}/>
  </ThemeProvider>;
}

function PageIntro({eyebrow,title,text,action}:{eyebrow:string;title:string;text:string;action?:React.ReactNode}) { return <Stack direction="row" alignItems="flex-end" justifyContent="space-between" sx={{mb:3}}><Box><Typography variant="overline" color="text.secondary">{eyebrow}</Typography><Typography variant="h1">{title}</Typography><Typography color="text.secondary" sx={{mt:.5}}>{text}</Typography></Box>{action}</Stack>; }
function Surface({children,sx}:{children:React.ReactNode;sx?:any}) { return <Paper variant="outlined" sx={{borderRadius:2,p:2,borderColor:"divider",...sx}}>{children}</Paper>; }
function StorageGate({created,kind,onClick}:{created?:boolean;kind:"scan"|"vault";onClick:()=>void}) { return <Surface sx={{py:4,px:3,maxWidth:720,mx:"auto",my:4}}><Stack spacing={1.5} alignItems="flex-start"><Lock color="primary"/><Typography variant="h2">{kind==="scan"?(created?"Scan storage is locked":"Set up encrypted scan storage"):"Credential vault is locked"}</Typography><Typography color="text.secondary">{kind==="scan"?"Sources, scan jobs and findings are available after scan storage is unlocked. The credential vault remains independent.":"Credential vault access has its own passphrase and does not affect scan storage."}</Typography><Button variant="contained" onClick={onClick}>{created?"Unlock scan storage":"Create scan storage"}</Button></Stack></Surface>; }
function Overview({sources,jobs,status,locked,onUnlock,onSources,onAdd,onScan}:{sources:Source[];jobs:Job[];status:any;locked:boolean;onUnlock:()=>void;onSources:()=>void;onAdd:()=>void;onScan:(id:string)=>void}) {
 const active=jobs.filter(activeJob).length;
 const latest=jobs.slice(0,3);
 return <><PageIntro eyebrow="PASSWORD BUDDY" title="Overview" text="A current view of configured sources and scan activity." action={<Button variant="contained" startIcon={<Add/>} onClick={sources.length?onSources:onAdd}>{sources.length?"Open sources":"Add source"}</Button>}/>
 {locked?<StorageGate created={status?.observations?.created} kind="scan" onClick={onUnlock}/>:<>
 <Box sx={{display:"grid",gridTemplateColumns:"repeat(2,minmax(180px,260px))",gap:2,mb:3}}><Surface><Typography variant="body2" color="text.secondary">Configured sources</Typography><Typography variant="h1" sx={{mt:.5}}>{sources.length}</Typography></Surface><Surface><Typography variant="body2" color="text.secondary">Active jobs</Typography><Typography variant="h1" sx={{mt:.5}}>{active}</Typography></Surface></Box>
 <SectionTitle title="Sources" action={<Button onClick={onSources}>Open sources</Button>}/>
 {sources.length===0?<EmptyState title="No sources yet" text="Add a folder or mounted share to create a scan scope." action={<Button variant="contained" onClick={onAdd}>Add source</Button>}/>:<Surface sx={{p:0,overflow:"hidden"}}><SourceTable sources={sources} onSelect={onSources} onScan={s=>onScan(s.id)}/></Surface>}
 <SectionTitle title="Recent scan activity"/>
 {latest.length===0?<EmptyState title="No scan jobs" text="Add a source and choose Scan now when you are ready."/>:<JobList jobs={latest} sources={sources} onAction={()=>undefined}/>}
 <SectionTitle title="Scan storage"/>
 <Surface><Typography fontWeight={600}>{status?.observations?.unlocked?"Unlocked":"Locked"}</Typography><Typography variant="body2" color="text.secondary">This store contains scan observations and review notes. Credential vault access is managed separately.</Typography><Typography variant="caption" color="text.secondary" display="block" sx={{mt:1}}>Latest scans: {latest.filter(j=>j.state==="completed").length} of {latest.length} complete</Typography></Surface>
 </>}
 </>;
}
function SectionTitle({title,action}:{title:string;action?:React.ReactNode}) { return <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{mt:3,mb:1}}><Typography variant="h3">{title}</Typography>{action}</Stack>; }
function EmptyState({title,text,action}:{title:string;text:string;action?:React.ReactNode}) { return <Surface sx={{py:3}}><Typography fontWeight={600}>{title}</Typography><Typography color="text.secondary" sx={{mt:.5,mb:action?2:0}}>{text}</Typography>{action}</Surface>; }
function SourceTable({sources,selected,onSelect,onScan}:{sources:Source[];selected?:string;onSelect?:(s:Source)=>void;onScan:(s:Source)=>void}) {
 return <Surface sx={{p:0,overflow:"hidden"}}>{sources.length===0?<Typography sx={{p:2}} color="text.secondary">No sources have been added.</Typography>:<Box sx={{overflowX:"auto"}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}><thead><tr>{["Source","Job state","Coverage","Last successful scan","Schedule",""].map(x=><th key={x} style={{textAlign:"left",padding:"12px 14px",borderBottom:"1px solid var(--mui-palette-divider)",color:"var(--mui-palette-text-secondary)",fontWeight:600}}>{x}</th>)}</tr></thead><tbody>{sources.map(s=>{const latestJob=(window as any).__unused; const state=s.enabled===false?"Disabled":s.last_success_at?"Previously completed":"Not yet checked"; return <tr key={s.id} onClick={()=>onSelect?.(s)} aria-selected={selected===s.id} style={{cursor:onSelect?"pointer":"default",background:selected===s.id?"var(--mui-palette-action-selected)":undefined}}><td style={{padding:14,borderBottom:"1px solid var(--mui-palette-divider)"}}><b>{s.label||s.root}</b><div className="path-text" style={{fontSize:12,color:"var(--mui-palette-text-secondary)",marginTop:4}}>{s.root}</div></td><td style={{padding:14,borderBottom:"1px solid var(--mui-palette-divider)"}}>{state}</td><td style={{padding:14,borderBottom:"1px solid var(--mui-palette-divider)"}}>{s.last_success_at?"Complete":"Not yet checked"}</td><td style={{padding:14,borderBottom:"1px solid var(--mui-palette-divider)"}}>{dateText(s.last_success_at)}</td><td style={{padding:14,borderBottom:"1px solid var(--mui-palette-divider)"}}>{scheduleText(s.schedule_seconds)}</td><td style={{padding:14,borderBottom:"1px solid var(--mui-palette-divider)"}}><Button size="small" onClick={e=>{e.stopPropagation();onScan(s);}}>Scan now</Button></td></tr>})}</tbody></table></Box>}</Surface>;
}
function SourceInspector({source,onScan,onEnable,onRemove}:{source?:Source;onScan:(s:Source)=>void;onEnable:(s:Source)=>void;onRemove:(s:Source)=>void}) {
 const [schedule,setSchedule]=useState(0);
 useEffect(()=>setSchedule(Number(source?.schedule_seconds)||0),[source?.id,source?.schedule_seconds]);
 if(!source) return <Surface><Typography fontWeight={600}>Select a source</Typography><Typography variant="body2" color="text.secondary">Choose a source row to inspect its scope and settings.</Typography></Surface>;
 return <Surface><Typography variant="h3">{source.label||"Source details"}</Typography><Typography className="path-text" variant="body2" sx={{my:1,overflowWrap:"anywhere"}}>{source.root}</Typography><Divider sx={{my:1.5}}/><Typography variant="caption" color="text.secondary">Source kind</Typography><Typography>{source.kind||"local"}</Typography><Typography variant="caption" color="text.secondary" display="block" sx={{mt:1}}>Latest coverage</Typography><Typography>{source.last_success_at?"Complete":"Not yet checked"}</Typography><Typography variant="caption" color="text.secondary" display="block" sx={{mt:1}}>Last successful scan</Typography><Typography>{dateText(source.last_success_at)}</Typography><Typography variant="caption" color="text.secondary" display="block" sx={{mt:1}}>Schedule</Typography><Typography>{scheduleText(source.schedule_seconds)}</Typography><Typography variant="caption" color="text.secondary" display="block" sx={{mt:1}}>Exclusions</Typography><Typography variant="body2">{(source.exclusions||[]).length?(source.exclusions||[]).join(", "):"None"}</Typography><Stack spacing={1} sx={{mt:2}}><Button variant="contained" onClick={()=>onScan(source)}>Scan now</Button><Button variant="outlined" onClick={()=>onEnable(source)}>{source.enabled===false?"Enable source":"Disable source"}</Button><Button color="error" onClick={()=>onRemove(source)}>Remove source</Button></Stack></Surface>;
}
function JobList({jobs,sources,onAction}:{jobs:Job[];sources:Source[];onAction:(j:Job,a:"pause"|"resume"|"cancel")=>void}) {
 if (!jobs.length) return <EmptyState title="No scan jobs yet" text="Scan activity appears here after you choose Scan now." />;
 return <Stack spacing={1}>{jobs.map(job=>{const source=sources.find(s=>s.id===job.source_id); return <Surface key={job.id}><Stack direction="row" justifyContent="space-between" alignItems="center" gap={2}><Box><Typography fontWeight={600}>{source?.label||source?.root||"Scan job"}</Typography><Typography variant="body2" color="text.secondary">{job.state}  {job.files_scanned??0} files checked{job.pending_files==null?"":"  "+job.pending_files+" pending"}  {coverageText(job.coverage)}</Typography>{job.last_error&&<Typography variant="caption" color="error.main">{job.last_error}</Typography>}{["running","queued","backoff"].includes(job.state)&&<LinearProgress sx={{mt:1,maxWidth:440}}/>}</Box><Stack direction="row">{["queued","running"].includes(job.state)&&<Button onClick={()=>onAction(job,"pause")} startIcon={<Pause/>}>Pause</Button>}{["paused","backoff"].includes(job.state)&&<Button onClick={()=>onAction(job,"resume")} startIcon={<PlayArrow/>}>Resume</Button>}{["queued","running","paused","backoff"].includes(job.state)&&<Button color="error" onClick={()=>onAction(job,"cancel")} startIcon={<Stop/>}>Cancel</Button>}</Stack></Stack></Surface>})}</Stack>;
}
function GitPlaceholder() { return <Surface><Typography variant="h3">Git guards</Typography><Typography variant="body2" color="text.secondary" sx={{my:1}}>Check guards for one repository at a time. Installing hooks is an explicit repository-level action.</Typography><Alert severity="info">Choose a repository path in Settings to inspect its current hooks.</Alert></Surface>; }
function SecondaryScreen({page,status,onRefresh}:{page:string;status:any;onRefresh:()=>void}) { return <><PageIntro eyebrow={page==="vault"?"ENCRYPTED LOCAL STORAGE":"LOCAL WORKSPACE"} title={pageTitle[page as Page]} text="This view is loading its live service state." action={<Button startIcon={<Refresh/>} onClick={onRefresh}>Refresh</Button>}/><Alert severity="info">Workspace data is not available until its API view is connected.</Alert></>; }
