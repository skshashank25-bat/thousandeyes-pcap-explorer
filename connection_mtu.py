"""Stage 4: capture-evidence TCP lifecycle and cautious MTU observations.

No live network probes; nothing here establishes endpoint interface or path MTU.
"""
from collections import defaultdict
import subprocess

FIELDS = ['frame.number','frame.time_epoch','ip.src','ip.dst','ip.len',
          'ip.flags.df','icmp.type','icmp.code','icmp.mtu','tcp.stream',
          'tcp.srcport','tcp.dstport','tcp.flags.syn','tcp.flags.ack',
          'tcp.flags.fin','tcp.flags.reset','tcp.seq','tcp.ack','tcp.len',
          'tcp.options.mss_val','tcp.analysis.retransmission']

def truth(value):
    return str(value).strip().lower() in ('true','1')

def integer(value):
    try: return int(str(value).strip())
    except (TypeError,ValueError): return None

def parse_rows(path):
    cmd=['tshark','-n','-r',str(path),'-T','fields','-E','separator=/t',
         '-E','occurrence=f','-E','quote=n']
    for f in FIELDS: cmd.extend(['-e',f])
    p=subprocess.run(cmd,capture_output=True,text=True,check=False)
    if p.returncode: raise RuntimeError(p.stderr.strip() or 'tshark failed')
    return [dict(zip(FIELDS, line.split('\t'))) for line in p.stdout.splitlines() if line.strip()]

def build_report(rows):
    groups=defaultdict(list)
    for p in rows:
        if p.get('tcp.stream','').strip()!='':
            groups[p['tcp.stream']].append(p)
    streams=[]
    mss_observations=[]
    for sid, packets in sorted(groups.items(),key=lambda x:int(x[0])):
        packets.sort(key=lambda p:integer(p.get('frame.number')) or 0)
        syns=[p for p in packets if truth(p.get('tcp.flags.syn')) and not truth(p.get('tcp.flags.ack'))]
        synacks=[p for p in packets if truth(p.get('tcp.flags.syn')) and truth(p.get('tcp.flags.ack'))]
        origin=syns[0].get('ip.src') if syns else packets[0].get('ip.src')
        responder=next((p.get('ip.src') for p in packets if p.get('ip.src')!=origin),None)
        fin=[p for p in packets if truth(p.get('tcp.flags.fin'))]
        resets=[p for p in packets if truth(p.get('tcp.flags.reset'))]
        ack_packets=[p for p in packets if truth(p.get('tcp.flags.ack')) and not truth(p.get('tcp.flags.syn'))]
        fin_signatures=set()
        fin_repeats=0
        for p in fin:
            signature=(p.get('ip.src'),p.get('tcp.seq'),p.get('tcp.ack'))
            if signature in fin_signatures: fin_repeats+=1
            fin_signatures.add(signature)
        # This is a capture-observed classification, not a claim about final TCP socket state.
        if not syns or not synacks:
            outcome='Handshake incomplete in capture'
        elif resets and fin:
            outcome='FIN exchange with RST observed'
        elif resets:
            outcome='RST observed'
        elif fin:
            outcome='FIN exchange observed' if len({p.get('ip.src') for p in fin})>1 else 'FIN observed (one side)'
        else:
            outcome='Handshake observed; no FIN/RST captured'
        events=[]
        for p in packets:
            labels=[]
            if truth(p.get('tcp.flags.syn')): labels.append('SYN-ACK' if truth(p.get('tcp.flags.ack')) else 'SYN')
            if truth(p.get('tcp.flags.fin')): labels.append('FIN')
            if truth(p.get('tcp.flags.reset')): labels.append('RST')
            if not labels: continue
            events.append({'frame':integer(p.get('frame.number')),
                           'time_epoch':float(p['frame.time_epoch']) if p.get('frame.time_epoch') else None,
                           'sender':p.get('ip.src'), 'event':'+'.join(labels),
                           'seq':integer(p.get('tcp.seq')),'ack':integer(p.get('tcp.ack')),
                           'tshark_retransmission':truth(p.get('tcp.analysis.retransmission'))})
        for p in syns+synacks:
            mss=integer(p.get('tcp.options.mss_val'))
            if mss is not None:
                mss_observations.append({'stream':int(sid),'sender':p.get('ip.src'),
                    'syn_type':'SYN-ACK' if truth(p.get('tcp.flags.ack')) else 'SYN',
                    'advertised_mss_bytes':mss,
                    'mss_plus_40_ipv4_bytes':mss+40,
                    'note':'MSS+40 is only a conventional IPv4/TCP header-size comparison, not actual interface/path MTU'})
        streams.append({'stream':int(sid),'initiator':origin,'responder':responder,
            'syn_sent':len(syns),'synack_received':len(synacks),
            'handshake_observed':bool(syns and synacks),
            'first_fin_sender':fin[0].get('ip.src') if fin else None,
            'fin_packets':len(fin),'repeated_fin_signatures':fin_repeats,
            'rst_packets':len(resets),'rst_senders':sorted({p.get('ip.src') for p in resets}),
            'ack_bearing_packets':len(ack_packets), 'outcome':outcome,'events':events})
    icmp=[]
    for p in rows:
        typ=integer(p.get('icmp.type'))
        if typ is None: continue
        icmp.append({'frame':integer(p.get('frame.number')),'src':p.get('ip.src'),
          'dst':p.get('ip.dst'),'type':typ,'code':integer(p.get('icmp.code')),
          'ip_total_length_bytes':integer(p.get('ip.len')),'df':truth(p.get('ip.flags.df')),
          'next_hop_mtu_bytes':integer(p.get('icmp.mtu'))})
    pmtu=[p for p in icmp if p['type']==3 and p['code']==4]
    df_echo=[p for p in icmp if p['type']==8 and p['df']]
    mtu={'source_interface_mtu_bytes':None,'target_interface_mtu_bytes':None,
         'confirmed_end_to_end_path_mtu_bytes':None,
         'mss_observations':mss_observations,
         'df_echo_requests':df_echo,
         'largest_df_echo_ip_packet_bytes':max((p['ip_total_length_bytes'] for p in df_echo if p['ip_total_length_bytes'] is not None),default=None),
         'fragmentation_needed_messages':pmtu,
         'reported_next_hop_mtus_bytes':sorted({p['next_hop_mtu_bytes'] for p in pmtu if p['next_hop_mtu_bytes'] is not None}),
         'notes':['Endpoint interface MTUs are not contained in ordinary TCP/IP packets.',
                  'Advertised MSS is not the actual interface or path MTU.',
                  'DF Echo Request size proves an attempted packet size, not end-to-end delivery.',
                  'ICMP Fragmentation Needed may provide a router-reported next-hop MTU; absence does not prove PMTU.',
                  'This is offline capture analysis; no network probing is performed.']}
    return {'streams':streams,'mtu':mtu}

def analyze_connection_mtu(path):
    return build_report(parse_rows(path))
