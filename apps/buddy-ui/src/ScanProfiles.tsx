import React, {useEffect, useState} from 'react';
import {Alert, Button, FormControl, InputLabel, MenuItem, Paper, Select, Stack, TextField, Typography} from '@mui/material';
import {request} from './api';

export default function ScanProfiles({revision, onApplied, onError}: {revision: number, onApplied: () => Promise<void>, onError: (message: string) => void}) {
 const [catalog, setCatalog] = useState<any>(null);
 const [preset, setPreset] = useState('standard');
 const [advanced, setAdvanced] = useState(false);
 const [document, setDocument] = useState(JSON.stringify({version:1,preset:'standard'}, null, 2));
 const [preview, setPreview] = useState<any>(null);
 const [busy, setBusy] = useState(false);
 const [message, setMessage] = useState('');
 async function load() { setCatalog(await request('/scan-profiles')); }
 useEffect(() => {void load().catch(e => onError(e.message));}, [revision]);
 async function run(action: () => Promise<void>) {
  setBusy(true); setMessage('');
  try {await action();} catch(e) {onError((e as Error).message);} finally {setBusy(false);}
 }
 function parsed() {
  try {return advanced ? JSON.parse(document) : {version:1,preset};}
  catch {throw new Error('Enter a valid JSON scan profile.');}
 }
 function select(id: string) {setPreset(id);setDocument(JSON.stringify({version:1,preset:id},null,2));setPreview(null);}
 if (!catalog) return null;
 return <Paper variant="outlined" sx={{p:2,mb:2}}>
  <Stack spacing={1.5}>
   <Typography variant="h3">Scanning profiles</Typography>
   <Typography variant="body2">Choose a preset or compose your own inspection packs and recurring jobs. Locations and their individual schedule overrides stay unchanged.</Typography>
   {catalog.current && <Typography variant="body2">Last applied: {catalog.current.document.preset}{catalog.current.customized ? ' · settings changed since application' : ' · settings match'}</Typography>}
   {catalog.record_error && <Alert severity="warning">The saved profile receipt could not be read.</Alert>}
   <FormControl size="small"><InputLabel>Scan preset</InputLabel><Select disabled={busy||advanced} label="Scan preset" value={preset} onChange={e=>select(e.target.value)}>
    {catalog.presets.map((p:any)=><MenuItem key={p.id} value={p.id}>{p.id==='standard'?'Standard credentials':p.id==='sensitive'?'Credentials and sensitive information':'Inventory metadata only'}</MenuItem>)}
   </Select></FormControl>
   <Button sx={{alignSelf:'flex-start'}} disabled={busy} onClick={()=>{setAdvanced(!advanced);setPreview(null);}}>{advanced?'Use preset controls':'Edit custom profile JSON'}</Button>
   {advanced && <><TextField label="Scan profile JSON" multiline minRows={6} maxRows={16} value={document} disabled={busy} onChange={e=>{setDocument(e.target.value);setPreview(null);}}/>
    {catalog.current && <Button disabled={busy} onClick={()=>{setDocument(JSON.stringify(catalog.current.document,null,2));setPreview(null);}}>Load last applied profile</Button>}</>}
   <Typography variant="caption">Existing custom recognizers are retained. Custom code must already be installed and trusted; applying a profile never downloads plugins. Native event monitoring, recursive archives and process-access auditing are not available in this version.</Typography>
   <Stack direction="row" spacing={1}><Button disabled={busy} onClick={()=>void run(async()=>{setPreview(await request('/scan-profiles/preview','POST',{document:parsed()}));})}>Preview changes</Button>
    <Button variant="contained" disabled={busy||!preview} onClick={()=>void run(async()=>{await request('/scan-profiles/apply','POST',{document:parsed(),expected_identity:preview.identity});setPreview(null);await load();await onApplied();setMessage('Scan profile applied. Configured jobs use the new settings when protection is running.');})}>Apply reviewed profile</Button></Stack>
   {preview && <><Typography variant="body2">{preview.inspection.mode==='inventory'?'Metadata inventory; content inspection disabled':'Content inspection'} · {preview.inspection.max_file_bytes.toLocaleString()} bytes per file · {preview.inspection.scan_workers} workers · {preview.components.length} configured extensions</Typography>
    <Typography variant="body2">Reconciliation: {preview.jobs.reconcile.mode==='daily'?'daily at '+preview.jobs.reconcile.daily_time+' '+preview.jobs.reconcile.timezone:'every '+preview.jobs.reconcile.interval_seconds/60+' minutes'}. Changes are discovered by polling.</Typography>
    <TextField label="Resolved profile details" multiline minRows={3} maxRows={12} value={JSON.stringify(preview,null,2)} slotProps={{input:{readOnly:true}}}/></>}
   {message && <Alert severity="success">{message}</Alert>}
  </Stack>
 </Paper>;
}
