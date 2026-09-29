import Database from 'better-sqlite3';
import { createHash, randomUUID } from 'node:crypto';

const db=new Database('data/jocky.db');
const now=new Date().toISOString();
const source=`INVESTIGATION "Suspicious Endpoint Activity" {
  TARGETS group("finance-endpoints")
  COLLECT SYSTEM.INFO
  COLLECT PROCESS.LIST
  COLLECT NETWORK.CONNECTIONS
  COLLECT FILE.HASH PATH "/Users/analyst/Downloads/invoice_update.exe"
  COLLECT EVENTS.LOGIN SINCE "24h"
  TIMELINE.CREATE
  CORRELATE PROCESS FILE NETWORK EVENT
  EVIDENCE.PRESERVE
  REPORT.GENERATE FORMAT "PDF"
}`;
const existing=db.prepare('SELECT count(*) AS count FROM endpoints').get() as {count:number};
if(existing.count){console.log('Local data already exists; seed was not applied.');process.exit(0)}
const endpoints=[
  ['1bca8053-33e3-48e0-8247-000000000001','FINANCE-WIN-07','windows','10.21.4.17'],
  ['1bca8053-33e3-48e0-8247-000000000002','FINANCE-WIN-12','windows','10.21.4.22'],
  ['1bca8053-33e3-48e0-8247-000000000003','FINANCE-UBU-03','linux','10.21.4.33']
];
for(const [id,hostname,os,ip] of endpoints)db.prepare('INSERT INTO endpoints VALUES (?,?,?,?,?,?,?,?,?,?)').run(id,hostname,os,ip,'1.0.0',JSON.stringify(['SYSTEM.INFO','PROCESS.LIST','NETWORK.CONNECTIONS','FILE.HASH','EVENTS.LOGIN']),'ONLINE',now,now,'local-demo');
const investigationId='2dba8053-33e3-48e0-8247-000000000001';
db.prepare('INSERT INTO investigations VALUES (?,?,?,?,?,?,?,?)').run(investigationId,'Suspicious Endpoint Activity',source,JSON.stringify(endpoints.map(x=>x[0])),'COMPLETED','local-demo',now,now);
const artifacts=[
  [endpoints[0][0],'FILE.HASH','file',{path:'/Users/analyst/Downloads/invoice_update.exe',sha256:'8b87f6d8c41070a8b78173ac91f3d44f2d106c6bd7d2aa4be629f1b0f52a4c21',size:184320}],
  [endpoints[0][0],'PROCESS.LIST','process',{pid:6840,executable:'invoice_update.exe',user:'analyst'}],
  [endpoints[0][0],'NETWORK.CONNECTIONS','network',{remoteAddress:'185.199.108.153',remotePort:443,processId:6840}],
  [endpoints[1][0],'FILE.HASH','file',{path:'C:\\Users\\analyst\\Downloads\\invoice_update.exe',sha256:'8b87f6d8c41070a8b78173ac91f3d44f2d106c6bd7d2aa4be629f1b0f52a4c21',size:184320}],
  [endpoints[2][0],'FILE.HASH','file',{path:'/home/analyst/Downloads/invoice_update.exe',sha256:'8b87f6d8c41070a8b78173ac91f3d44f2d106c6bd7d2aa4be629f1b0f52a4c21',size:184320}]
];
for(const [endpointId,collector,type,content] of artifacts as [string,string,string,unknown][]){const payload=JSON.stringify(content);const evidenceId=randomUUID();const hash=createHash('sha256').update(payload).digest('hex');db.prepare('INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?,?,?)').run(evidenceId,investigationId,endpointId,collector,type,payload,hash,JSON.stringify({source:'LOCAL_DEMO_DATASET',normalizationVersion:'1.0'}),now,now);db.prepare('INSERT INTO custody VALUES (?,?,?,?,?,?)').run(randomUUID(),evidenceId,'local-demo-agent','COLLECTED',JSON.stringify({sha256:hash,integrity:'VERIFIED'}),now)}
for(const action of ['dataset.seeded','investigation.created','evidence.verified'])db.prepare('INSERT INTO audit_logs VALUES (?,?,?,?,?,?,?)').run(randomUUID(),'local-demo',action,'local-dataset',investigationId,JSON.stringify({localOnly:true}),now);
console.log('Local JOCKY sample dataset created: 3 endpoints, 1 investigation, 5 evidence items.');
