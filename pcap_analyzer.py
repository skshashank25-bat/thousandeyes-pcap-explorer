#!/usr/bin/env python3
"""Read-only PCAP analysis using Wireshark's tshark dissectors."""
import argparse
import collections
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

FIELDS = [
    'frame.number','frame.time_epoch','frame.len','ip.src','ip.dst','ip.ttl','ip.len','ip.flags.df','ip.flags.mf','ip.frag_offset',
    'tcp.stream','tcp.srcport','tcp.dstport','tcp.flags.syn','tcp.flags.ack',
    'tcp.flags.reset','tcp.flags.fin','tcp.seq','tcp.ack','tcp.len',
    'tcp.options.mss_val','tcp.options.sack_perm','tcp.options.sack_le',
    'tcp.analysis.retransmission','tcp.analysis.fast_retransmission',
    'tcp.analysis.duplicate_ack','tcp.analysis.zero_window',
    'udp.srcport','udp.dstport','dns.qry.name','dns.flags.response',
    'dns.flags.rcode','dns.time','tls.handshake.type','icmp.type','icmp.code',
]


def tshark_packets(path):
    command = ['tshark','-n','-r',str(path),'-T','fields','-E','separator=/t',
               '-E','occurrence=f','-E','quote=n']
    for field in FIELDS:
        command += ['-e',field]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'TShark failed')
    packets=[]
    for line in result.stdout.splitlines():
        parts=line.split('\t')
        packets.append(dict(zip(FIELDS, parts + [''] * (len(FIELDS)-len(parts)))))
    return packets


def yes(packet, field):
    return str(packet.get(field, '')).strip().lower() in ('true','1')


def asint(value):
    try:
        return int(value)
    except (TypeError,ValueError):
        return None


def asfloat(value):
    try:
        return float(value)
    except (TypeError,ValueError):
        return None


def analyze(path):
    packets=tshark_packets(path)
    counts=collections.Counter()
    streams={}
    dns=[]
    icmp_observations=[]
    tcp_direction=collections.defaultdict(collections.Counter)
    for p in packets:
        if p.get('tcp.stream'):
            counts['tcp']+=1
            sid=p['tcp.stream']
            direction=(p['ip.src'],p['ip.dst'])
            dc=tcp_direction[direction]
            syn_flag=yes(p,'tcp.flags.syn')
            ack_flag=yes(p,'tcp.flags.ack')
            if syn_flag and not ack_flag:dc['syn_only']+=1
            if syn_flag and ack_flag:dc['syn_ack']+=1
            if ack_flag:dc['ack_flag']+=1
            if ack_flag and not syn_flag:dc['ack_without_syn']+=1
            if yes(p,'tcp.flags.reset'):dc['rst']+=1
            if yes(p,'tcp.flags.fin'):dc['fin']+=1
            if p['tcp.options.sack_le']:dc['sack_packets']+=1
            if p['tcp.options.sack_perm']:dc['sack_permitted']+=1
            dc['packets']+=1
            s=streams.setdefault(sid, {
                'stream':int(sid),'packets':0,'bytes_on_wire':0,
                'endpoints':[], 'first_epoch':None,'last_epoch':None,
                'syn':0,'syn_ack':0,'rst':0,'fin':0,'sack_blocks':0,
                'retransmission_flags':0,'fast_retransmission_flags':0,
                'duplicate_ack_flags':0,'zero_window_flags':0,
                'mss_advertised':[], 'sack_permitted_frames':[],
                'ttl_observations':{},'syn_frames':[], 'syn_ack_frames':[],
                'retransmission_frames':[], 'sack_frames':[],
                'sequence_overlap_evidence':[], 'handshake_rtt_ms':None,
            })
            s['packets']+=1
            s['bytes_on_wire']+=asint(p['frame.len']) or 0
            epoch=asfloat(p['frame.time_epoch'])
            if epoch is not None:
                s['first_epoch']=epoch if s['first_epoch'] is None else min(s['first_epoch'],epoch)
                s['last_epoch']=epoch if s['last_epoch'] is None else max(s['last_epoch'],epoch)
            endpoint=f"{p['ip.src']}:{p['tcp.srcport']}"
            if endpoint not in s['endpoints']:
                s['endpoints'].append(endpoint)
            frame=asint(p['frame.number'])
            syn=yes(p,'tcp.flags.syn')
            ack=yes(p,'tcp.flags.ack')
            if syn and not ack:
                s['syn']+=1
                s['syn_frames'].append({'frame':frame,'epoch':epoch,'src':p['ip.src'],'dst':p['ip.dst']})
            if syn and ack:
                s['syn_ack']+=1
                s['syn_ack_frames'].append({'frame':frame,'epoch':epoch,'src':p['ip.src'],'dst':p['ip.dst']})
            if yes(p,'tcp.flags.reset'):s['rst']+=1
            if yes(p,'tcp.flags.fin'):s['fin']+=1
            if p['tcp.options.sack_le']:
                s['sack_blocks']+=1
                s['sack_frames'].append(frame)
            if p['tcp.options.sack_perm']:
                s['sack_permitted_frames'].append(frame)
            if p['tcp.options.mss_val']:
                s['mss_advertised'].append({'frame':frame,'src':p['ip.src'],'mss':asint(p['tcp.options.mss_val'])})
            if p['ip.ttl']:
                s['ttl_observations'][p['ip.src']]=asint(p['ip.ttl'])
            for field,key in [('tcp.analysis.retransmission','retransmission_flags'),
                              ('tcp.analysis.fast_retransmission','fast_retransmission_flags'),
                              ('tcp.analysis.duplicate_ack','duplicate_ack_flags'),
                              ('tcp.analysis.zero_window','zero_window_flags')]:
                if p[field]:s[key]+=1
            if p['tcp.analysis.retransmission']:
                s['retransmission_frames'].append(frame)
            # Record suspicious overlap when sequence increases less than previous payload length.
            seq=asint(p['tcp.seq']); payload=asint(p['tcp.len']) or 0
            if seq is not None and payload > 0:
                previous=s.setdefault('_last_payload_by_sender',{}).get(p['ip.src'])
                if previous and previous['seq'] < seq < previous['seq']+previous['len']:
                    s['sequence_overlap_evidence'].append({'frame':frame,'previous_frame':previous['frame'],
                        'sequence':seq,'previous_sequence':previous['seq'],'payload_bytes':payload})
                s['_last_payload_by_sender'][p['ip.src']]={'seq':seq,'len':payload,'frame':frame}
        elif p.get('udp.srcport'):
            counts['udp']+=1
        elif p.get('icmp.type'):
            counts['icmp']+=1
            icmp_observations.append({'frame':asint(p['frame.number']), 'src':p['ip.src'],
                'dst':p['ip.dst'],'type':asint(p['icmp.type']),'code':asint(p['icmp.code']),
                'ip_length':asint(p['ip.len']),'frame_length':asint(p['frame.len']),
                'ttl':asint(p['ip.ttl']),'df':yes(p,'ip.flags.df'),
                'mf':yes(p,'ip.flags.mf'),'fragment_offset':asint(p['ip.frag_offset'])})
        else:
            counts['other']+=1
        if p.get('dns.qry.name'):
            dns.append({'frame':asint(p['frame.number']),'name':p['dns.qry.name'],
                        'is_response':p['dns.flags.response']=='1','rcode':p['dns.flags.rcode'],
                        'response_time_seconds':asfloat(p['dns.time'])})
    output_streams=[]
    for s in streams.values():
        for syn in s['syn_frames']:
            match=next((reply for reply in s['syn_ack_frames'] if reply['src']==syn['dst']
                        and reply['dst']==syn['src'] and reply['epoch'] is not None
                        and syn['epoch'] is not None and reply['epoch']>=syn['epoch']),None)
            if match:
                s['handshake_rtt_ms']=round((match['epoch']-syn['epoch'])*1000,3)
                break
        s['duration_seconds']=round(s['last_epoch']-s['first_epoch'],6) if s['first_epoch'] is not None else None
        s['probe_like_overlap']=len(s['sequence_overlap_evidence'])>=3
        s['retransmission_interpretation']=('Overlapping TCP sequence ranges: may be synthetic probe traffic; do not equate flags to packet loss'
            if s['probe_like_overlap'] else 'TShark flags only; inspect sequence and capture context before inferring loss')
        s.pop('_last_payload_by_sender',None)
        output_streams.append(s)
    output_streams.sort(key=lambda x:x['stream'])
    directions=[{'src':src,'dst':dst,**dict(c)} for (src,dst),c in sorted(tcp_direction.items())]
    source=next((d['src'] for d in directions if d.get('syn_only', 0)>0),None)
    target=next((d['dst'] for d in directions if d['src']==source and d.get('syn_only', 0)>0),None)
    forward=next((d for d in directions if d['src']==source and d['dst']==target),{})
    reverse=next((d for d in directions if d['src']==target and d['dst']==source),{})
    observed_syn=forward.get('syn_only',0)
    observed_synack=reverse.get('syn_ack',0)
    forward_ttls=sorted({asint(p['ip.ttl']) for p in packets if p['ip.src']==source and p['ip.dst']==target and p['ip.ttl'] and yes(p,'tcp.flags.syn')})
    reverse_ttls=sorted({asint(p['ip.ttl']) for p in packets if p['ip.src']==target and p['ip.dst']==source and p['ip.ttl'] and yes(p,'tcp.flags.syn')})
    mtu_candidates=[i for i in icmp_observations if i['type']==8 and i['df'] and i['ip_length']==1500]
    measurement={'source_ip':source,'target_ip':target,'measurement_type':'agent-to-server (configured)',
        'tcp_directions':directions,
        'syn_sent':observed_syn,'syn_ack_received':observed_synack,
        'syn_minus_synack_raw':observed_syn-observed_synack,
        'note':'Raw SYN and SYN-ACK totals do not by themselves establish probe loss or one-to-one response matching.',
        'sack_response_packets':reverse.get('sack_packets',0),
        'clock_sync_preamble':{'applicable':False,'reason':'5+5 preamble applies to agent-to-agent measurements, not this agent-to-server test.'},
        'path':{'forward_hops':None,'forward_syn_ttls':forward_ttls,'incoming_synack_ttls':reverse_ttls,
                'reverse_hop_estimate_if_initial_ttl_128':128-reverse_ttls[0] if len(reverse_ttls)==1 and reverse_ttls[0]<=128 else None,
                'note':'Reverse hop estimate assumes initial TTL 128; forward hop count cannot be inferred from normal SYN TTL.'},
        'icmp':{'observations':icmp_observations,'echo_requests':sum(i['type']==8 for i in icmp_observations),
                'echo_replies':sum(i['type']==0 for i in icmp_observations),
                'time_exceeded':sum(i['type']==11 for i in icmp_observations),
                'fragmentation_needed':sum(i['type']==3 and i['code']==4 for i in icmp_observations),
                'full_size_df_echo_requests':len(mtu_candidates),
                'note':'Full-size DF echo requests are consistent with MTU probing but do not prove MTU failure.'}}
    return {'capture':str(path),'generated_at_utc':datetime.now(timezone.utc).isoformat(),
            'summary':{'packets':len(packets),'protocol_counts':dict(counts),
                       'tcp_streams':len(output_streams),'dns_records':len(dns),
                       'probe_like_streams':sum(s['probe_like_overlap'] for s in output_streams)},
            'streams':output_streams,'dns':dns,'measurement':measurement,
            'caveats':['Retransmission flags do not establish network packet loss, especially for synthetic probes.',
                       'Observed TTL does not prove hop count without known initial TTL.',
                       'Advertised MSS does not directly measure path MTU.',
                       'Filtered captures may omit DNS and other protocols.']}


def main():
    parser=argparse.ArgumentParser(description='ThousandEyes-aware PCAP analyzer')
    parser.add_argument('capture',type=Path)
    parser.add_argument('--output',type=Path,default=Path('reports/analysis.json'))
    args=parser.parse_args()
    if not args.capture.is_file():parser.error(f'Capture not found: {args.capture}')
    try:report=analyze(args.capture)
    except (RuntimeError,OSError) as exc:parser.error(str(exc))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2))
    summary=report['summary']
    print(f"Packets: {summary['packets']} | TCP streams: {summary['tcp_streams']} | Probe-like streams: {summary['probe_like_streams']}")
    print(f'JSON saved: {args.output}')
    m=report['measurement']
    print(f"SYN sent: {m['syn_sent']} | SYN-ACK received: {m['syn_ack_received']} | SACK response packets: {m['sack_response_packets']}")
    print(f"ICMP 1500-byte DF echo requests: {m['icmp']['full_size_df_echo_requests']} | Forward hops: unknown")
    print('Top streams by packets:')
    for s in sorted(report['streams'],key=lambda x:x['packets'],reverse=True)[:8]:
        print(f"  Stream {s['stream']:>3}: {s['packets']:>4} packets | RTT {s['handshake_rtt_ms']} ms | "
              f"retrans flags {s['retransmission_flags']} | probe-like {s['probe_like_overlap']}")

if __name__=='__main__':main()
