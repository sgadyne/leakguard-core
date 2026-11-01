import { Box, Button, Chip, Paper, Stack, Typography } from "@mui/material";
import { LockOutlined, FolderOpenOutlined } from "@mui/icons-material";
import type { ReactNode } from "react";

/** Shared presentation only. Live facts always come from the authenticated API. */
export function PageHeader({eyebrow,title,text,action}:{eyebrow:string;title:string;text:string;action?:ReactNode}) {
 return <Stack className="page-header" direction="row" useFlexGap sx={{alignItems:"flex-end",justifyContent:"space-between",mb:3,gap:2,flexWrap:"wrap"}}><Box sx={{minWidth:0,flex:"1 1 360px"}}><Typography variant="overline" color="text.secondary">{eyebrow}</Typography><Typography variant="h1">{title}</Typography><Typography color="text.secondary" sx={{mt:.75,maxWidth:800}}>{text}</Typography></Box>{action}</Stack>;
}
export function Surface({children,sx}:{children:ReactNode;sx?:object}) {return <Paper variant="outlined" sx={{p:2.5,borderRadius:3.5,minWidth:0,...sx}}>{children}</Paper>;}
export function EmptyState({title,text,action,locked=false}:{title:string;text:string;action?:ReactNode;locked?:boolean}) {
 return <Surface sx={{py:4}}><Stack spacing={1.5} sx={{alignItems:"flex-start"}}>{locked?<LockOutlined color="primary" sx={{fontSize:32}}/>:<FolderOpenOutlined color="primary" sx={{fontSize:32}}/>}<Typography variant="h2">{title}</Typography><Typography color="text.secondary" sx={{maxWidth:660}}>{text}</Typography>{action}</Stack></Surface>;
}
export function EvidenceMetric({label,value,text}:{label:string;value:number|null|undefined;text:string}) {
 return <Surface><Typography variant="overline" color="text.secondary">{label}</Typography><Typography sx={{fontWeight:650,fontSize:value==null?23:32,lineHeight:1.3,my:.75,color:"primary.main"}}>{value==null?"Not measured":value.toLocaleString()}</Typography><Typography variant="body2" color="text.secondary">{text}</Typography></Surface>;
}
export function StoreBadge({name,store}:{name:string;store?:{created?:boolean;unlocked?:boolean;available?:boolean}}) {
 const label=!store?"Unknown":store.available===false?"Unavailable":store.unlocked?"Unlocked":store.created?"Locked":"Not created";
 return <Stack direction="row" spacing={.75} sx={{alignItems:"center"}}><LockOutlined sx={{fontSize:14}}/><Typography variant="caption">{name}: {label}</Typography></Stack>;
}
export function StateLabel({label,warning=false}:{label:string;warning?:boolean}) {return <Chip size="small" color={warning?"warning":"default"} variant="outlined" label={label}/>;}
