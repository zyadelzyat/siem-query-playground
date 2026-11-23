"""Read supplied logs without modifying them; emit lazy-loaded gzip datasets."""
from pathlib import Path
from datetime import datetime, timezone
import csv, gzip, hashlib, json, re, collections, ast, sys

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('logs')
OUT = Path(__file__).parent / 'dist' / 'datasets'
OUT.mkdir(exist_ok=True)
TITLES = {
 'aadinternals_export_adfsdatabaseconfig_remotely': 'Remote ADFS database export',
 'aptsimulator_cobaltstrike': 'APT Simulator · Cobalt Strike',
 'auditpol_system_user_auditpolicy_modification': 'Audit policy modification',
 'aws_s3_honeybucketlogs': 'AWS S3 honeybucket activity',
 'cmd_psh_stop_netprofm_eventlog_after_reboot': 'Service stopping · CMD / PowerShell · after reboot',
 'cmd_psh_stop_netprofm_eventlog_before_reboot': 'Service stopping · CMD / PowerShell · before reboot',
 'cmd_wevtutil_modify_security_eventlog_path': 'Security log path modification · wevtutil',
 'ec2_proxy_s3_exfiltration': 'EC2 proxy / S3 activity',
 'psh_metasploit_stop_netprofm_eventlog_after_reboot': 'Service stopping · Metasploit · after reboot',
 'psh_metasploit_stop_netprofm_eventlog_before_reboot': 'Service stopping · Metasploit · before reboot',
 'reg_cmd_process_commandline_logging_disabled': 'Command-line logging disabled · CMD',
 'reg_meterpreter_process_commandline_logging_disabled': 'Command-line logging disabled · Meterpreter',
 'schtask_modification': 'Scheduled task modification',
 'sh_arp_cache': 'Linux · ARP cache discovery',
 'sh_binary_padding_dd': 'Linux · binary padding with dd',
}
def iso(value):
 if not value: raise ValueError('A source record has no timestamp')
 return datetime.fromisoformat(str(value).replace('Z','+00:00')).astimezone(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
def val(*values):
 return next((str(v) for v in values if v not in (None, '', '-')), '')
def normalize(obj, raw, number, kind):
 if kind=='Windows':
  code=obj.get('EventID',''); code=int(code) if str(code).isdigit() else str(code)
  channel=val(obj.get('Channel'),obj.get('SourceName'))
  event_type=f'{channel}:{code}'
  return dict(id=number,time=iso(obj.get('@timestamp') or obj.get('TimeCreated')),code=code,eventType=event_type,
   user=val(obj.get('User'),obj.get('TargetUserName'),obj.get('SubjectUserName')),
   ip=val(obj.get('IpAddress'),obj.get('SourceIp'),obj.get('SourceAddress')),
   host=val(obj.get('Hostname'),obj.get('Computer')),channel=channel,
   process=val(obj.get('Image'),obj.get('NewProcessName'),obj.get('ProcessName'),obj.get('Application')),
   command=val(obj.get('CommandLine'),obj.get('ProcessCommandLine')),raw=raw)
 if kind=='CloudTrail':
  ident=obj.get('userIdentity') or {}
  return dict(id=number,time=iso(obj.get('@timestamp') or obj.get('eventTime')),code=val(obj.get('eventName')),
   eventType=val(obj.get('eventSource'))+':'+val(obj.get('eventName')),
   user=val(ident.get('userName'),ident.get('arn'),ident.get('principalId')),ip=val(obj.get('sourceIPAddress')),
   host='',channel=val(obj.get('eventSource')),process='',command='',raw=raw)
 if kind=='S3 CSV':
  ident=ast.literal_eval(obj.get('User ID') or '{}')
  return dict(id=number,time=iso(obj.get('Event DateTime')),code=obj.get('Event Name',''),eventType='S3:'+obj.get('Event Name',''),
   user=val(ident.get('userName'),ident.get('principalId'),ident.get('accountId')),ip=val(obj.get('Source IP')),host='',
   channel=val(obj.get('Event Type')),process='',command='',raw=raw)
 match=re.search(r'audit\((\d+\.\d+):(\d+)\)',raw)
 if not match: raise ValueError('Unrecognized audit timestamp')
 pairs={m[1]:(m[2] if m[2] is not None else m[3]) for m in re.finditer(r'(\w+)=(?:"([^"]*)"|(\S+))',raw)}
 code=pairs.get('type','audit')
 return dict(id=number,time=datetime.fromtimestamp(float(match[1]),timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z'),
  code=code,eventType='audit:'+code,user=val(pairs.get('auid'),pairs.get('uid')),ip='',host='',channel='Linux audit',
  process=val(pairs.get('exe'),pairs.get('comm')),command=' '.join(pairs.get(f'a{i}','') for i in range(int(pairs.get('argc','0')))).strip(),raw=raw)

manifest={'version':2,'source':'G:\\final logs','upstream':{'name':'Security Datasets','url':'https://securitydatasets.com/introduction.html','repository':'https://github.com/OTRF/Security-Datasets','licenseNotice':'licenses/security-datasets-MIT.txt'},'datasets':[],'excluded':[]}
for path in sorted(ROOT.rglob('*')):
 if not path.is_file(): continue
 rel=str(path.relative_to(ROOT)).replace('\\','/')
 if '__MACOSX' in path.parts or path.name.startswith('._'):
  manifest['excluded'].append({'file':rel,'reason':'macOS metadata'});continue
 if path.suffix.lower()=='.zip':
  manifest['excluded'].append({'file':rel,'reason':'Archive duplicate; extracted log used'});continue
 if path.suffix.lower() not in ('.json','.csv','.log'):
  manifest['excluded'].append({'file':rel,'reason':'Packet capture; requires packet decoding before SIEM queries'});continue
 slug=path.parent.name
 rows=[]
 if path.suffix=='.json':
  with path.open(encoding='utf-8-sig') as f:
   for line in f:
    if not line.strip(): continue
    obj=json.loads(line);kind='Windows' if 'EventID' in obj else 'CloudTrail'
    rows.append(normalize(obj,line.rstrip('\r\n'),len(rows)+1,kind))
 elif path.suffix=='.csv':
  kind='S3 CSV'
  with path.open(encoding='utf-8-sig',newline='') as f:
   for obj in csv.DictReader(f):
    rows.append(normalize(obj,json.dumps(obj,ensure_ascii=False),len(rows)+1,kind))
 else:
  kind='Linux audit'
  for line in path.read_text(encoding='utf-8-sig').splitlines():
   if line.strip():rows.append(normalize({},line,len(rows)+1,kind))
 counts=collections.Counter(r['eventType'] for r in rows)
 types=sorted(counts)
 target=next((t for t in types if any(s in t for s in [':4719',':4702',':4657'])),None)
 if not target: target=next((t for t in types if 'Sysmon' in t and t.endswith(':1')),None)
 if not target:target=next((t for t in types if t.endswith(':4688')),None)
 if not target:target=counts.most_common(1)[0][0]
 terms=['auditpol','wevtutil','schtasks','reg.exe','powershell','GetObject','ListObjects','arp','dd','adfs']
 preferred=[x for x in terms if x in slug.lower()]+terms
 hunt=next((term for term in preferred if any(term.lower() in r['raw'].lower() for r in rows)),None)
 if hunt is None: hunt=str(rows[0]['code'])
 data={'rows':rows}
 blob=json.dumps(data,ensure_ascii=False,separators=(',',':')).encode()
 filename=slug+'.json.gz'
 (OUT/filename).write_bytes(gzip.compress(blob,compresslevel=9,mtime=0))
 entry={'id':slug,'title':TITLES.get(slug,slug.replace('_',' ')),'file':filename,'sourceFile':rel,'format':kind,
  'count':len(rows),'start':min(r['time'] for r in rows),'clock':max(r['time'] for r in rows),
  'sourceSha256':hashlib.sha256(path.read_bytes()).hexdigest(),'compressedBytes':(OUT/filename).stat().st_size,
  'targetType':target,'huntTerm':hunt,'targetUser':next((r['user'] for r in rows if r['user']),''),
  'threshold':max(0,counts.most_common(1)[0][1]//2),'eventTypes':dict(counts),
  'missing':{f:sum(not r[f] for r in rows) for f in ['user','ip','host','process','command']}}
 manifest['datasets'].append(entry)
 print(f'{slug}: {len(rows):,} records, {entry["compressedBytes"]:,} bytes compressed')
(OUT/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
print('TOTAL',sum(x['count'] for x in manifest['datasets']),'records in',len(manifest['datasets']),'datasets')
