"""Interactive PCAP explorer; uses the same analysis engine as the CLI."""
import json
import subprocess
import tempfile
from pathlib import Path
import pandas as pd
import streamlit as st
from pcap_analyzer import analyze, tshark_packets
from probe_analysis import extract_sack_edges, analyze_probe_candidates
from sack_progression import analyze_sack_progression
from connection_mtu import analyze_connection_mtu
from mtu_validation import LAB, PROBES, summarize
from troubleshooting_insights import build_insights
import altair as alt

st.set_page_config(page_title='ThousandEyes PCAP Explorer',layout='wide')
st.title('ThousandEyes PCAP Explorer')
st.caption('TShark-backed analysis · TCP streams · probe-aware retransmission interpretation')
upload=st.file_uploader('Upload a PCAP or PCAPNG file',type=['pcap','pcapng'])
if not upload:
    st.info('Upload a capture to begin. The CLI uses the same analyzer.')
    st.stop()
with tempfile.TemporaryDirectory(prefix='pcap_explorer_') as folder:
    path=Path(folder)/upload.name
    path.write_bytes(upload.getvalue())
    try:
        with st.spinner('Analyzing capture with TShark...'):
            report=analyze(path)
            raw_packets=tshark_packets(path)
            stage4=analyze_connection_mtu(path)
    except Exception as exc:
        st.error(f'Analysis failed: {exc}')
        st.stop()
st.markdown('### Explore the capture by stage')
tab_overview, tab_tcp, tab_mtu, tab_insights = st.tabs(['Overview', 'Stages 1–3 · TCP & SACK', 'Stage 4 · Connections & MTU', 'Stage 5 · Insights'])

with tab_overview:
    summary=report['summary']
    a,b,c,d=st.columns(4)
    a.metric('Packets',summary['packets'])
    b.metric('TCP streams',summary['tcp_streams'])
    c.metric('Probe-like streams',summary['probe_like_streams'])
    d.metric('DNS records',summary['dns_records'])
    st.subheader('Network Measurement Summary')
    m=report['measurement']
    x,y,z=st.columns(3)
    x.metric('SYN sent',m['syn_sent'])
    y.metric('SYN-ACK received',m['syn_ack_received'])
    z.metric('SACK-bearing responses',m['sack_response_packets'])
    st.caption('SYN/SYN-ACK totals are raw counts, not independently verified probe-loss measurements.')
    st.markdown('**TCP flags by direction**')
    st.dataframe(pd.DataFrame(m['tcp_directions']),hide_index=True,use_container_width=True)
    st.subheader('Path, ICMP and MTU')
    a,b,c,d=st.columns(4)
    a.metric('Forward hops','Unknown')
    b.metric('Reverse hops (estimated)',str(m['path']['reverse_hop_estimate_if_initial_ttl_128']) if m['path']['reverse_hop_estimate_if_initial_ttl_128'] is not None else 'Unknown')
    c.metric('ICMP Echo Requests',m['icmp']['echo_requests'])
    d.metric('1500-byte DF Echo Requests',m['icmp']['full_size_df_echo_requests'])
    st.caption('Reverse-hop estimate assumes initial TTL 128. Clock sync preamble (5 each direction): not applicable to this Agent-to-Server test.')
    st.caption(m['icmp']['note'])
    with st.expander('ICMP packet details'):
        st.dataframe(pd.DataFrame(m['icmp']['observations']),hide_index=True,use_container_width=True)

with tab_tcp:
    st.download_button('Download JSON report',json.dumps(report,indent=2),file_name='pcap_report.json',mime='application/json')
    streams=report['streams']
    if streams:
        df=pd.DataFrame([{'stream':s['stream'],'endpoints':' ↔ '.join(s['endpoints']),
            'packets':s['packets'],'duration_s':s['duration_seconds'],'syn':s['syn'],
            'syn_ack':s['syn_ack'],'rtt_ms':s['handshake_rtt_ms'],
            'retrans_flags':s['retransmission_flags'],'sack_blocks':s['sack_blocks'],
            'probe_like':s['probe_like_overlap']} for s in streams])
        st.subheader('TCP conversations')
        st.dataframe(df,hide_index=True,use_container_width=True)
        st.subheader('Largest conversations')
        st.bar_chart(df.nlargest(12,'packets').set_index('stream')['packets'])
        sid=st.selectbox('Inspect TCP stream',options=[s['stream'] for s in streams],
            index=next((i for i,s in enumerate(streams) if s['probe_like_overlap']),0))
        stream=next(s for s in streams if s['stream']==sid)
        st.json(stream,expanded=False)
        st.code(f'tcp.stream == {sid}',language='text')
        st.caption('Copy this filter into Wireshark, or use the CLI command below to export this conversation.')
        st.code(f'tshark -r "your_capture.pcap" -Y "tcp.stream == {sid}" -w "stream_{sid}.pcap"',language='bash')
        st.subheader(f'Packet-level inspector — TCP stream {sid}')
        selected = [p for p in raw_packets if p.get('tcp.stream') == str(sid)]

        def flag_on(p, field):
            return str(p.get(field, '')).strip().lower() in ('true', '1')

        def number(value, default=0):
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        def timestamp(value):
            try:
                return float(value)
            except (TypeError, ValueError):
                return 0.0

        first_capture_time = min((timestamp(p.get('frame.time_epoch')) for p in raw_packets), default=0.0)
        source_ip = next((p.get('ip.src') for p in selected if flag_on(p, 'tcp.flags.syn') and not flag_on(p, 'tcp.flags.ack')), selected[0].get('ip.src') if selected else None)
        rows = []
        for p in selected:
            syn = flag_on(p, 'tcp.flags.syn')
            ack = flag_on(p, 'tcp.flags.ack')
            rst = flag_on(p, 'tcp.flags.reset')
            fin = flag_on(p, 'tcp.flags.fin')
            flags = '+'.join(name for name, enabled in (
                ('SYN', syn), ('ACK', ack), ('RST', rst), ('FIN', fin)) if enabled) or 'Other'
            retrans = flag_on(p, 'tcp.analysis.retransmission') or flag_on(p, 'tcp.analysis.fast_retransmission')
            sack = str(p.get('tcp.options.sack_le', '')).strip()
            rows.append({
                'frame': number(p.get('frame.number')),
                'time_s': round(timestamp(p.get('frame.time_epoch')) - first_capture_time, 6),
                'direction': 'TEVA → target' if p.get('ip.src') == source_ip else 'Target → TEVA',
                'src': p.get('ip.src', ''), 'dst': p.get('ip.dst', ''),
                'flags': flags, 'seq': number(p.get('tcp.seq')),
                'ack_num': number(p.get('tcp.ack')),
                'tcp_payload_bytes': number(p.get('tcp.len')),
                'retrans_label': retrans,
                'sack_left_edge': sack,
                'syn': syn, 'syn_ack': syn and ack,
                'sack_response': bool(sack),
            })
        packets_df = pd.DataFrame(rows)
        if not packets_df.empty:
            a, b, c, d = st.columns(4)
            a.metric('Stream packets', len(packets_df))
            b.metric('TCP payload packets', int((packets_df['tcp_payload_bytes'] > 0).sum()))
            c.metric('Retransmission labels', int(packets_df['retrans_label'].sum()))
            d.metric('SACK-bearing packets', int(packets_df['sack_response'].sum()))

            choices = ['All packets', 'SYN', 'SYN-ACK', 'TCP payload', 'SACK responses', 'Retransmission-labelled']
            selection = st.selectbox('Packet filter', choices, key='packet_filter')
            filtered = packets_df
            if selection == 'SYN':
                filtered = filtered[filtered['syn'] & ~filtered['syn_ack']]
            elif selection == 'SYN-ACK':
                filtered = filtered[filtered['syn_ack']]
            elif selection == 'TCP payload':
                filtered = filtered[filtered['tcp_payload_bytes'] > 0]
            elif selection == 'SACK responses':
                filtered = filtered[filtered['sack_response']]
            elif selection == 'Retransmission-labelled':
                filtered = filtered[filtered['retrans_label']]
            st.dataframe(filtered.drop(columns=['syn', 'syn_ack', 'sack_response']),
                         hide_index=True, use_container_width=True, height=360)
            st.caption('SACK left edge shows the first occurrence extracted by the analyzer; it is not a complete SACK block listing.')

            st.markdown('**TCP sequence number vs. elapsed stream time**')
            chart_df = packets_df.loc[packets_df['tcp_payload_bytes'] > 0,
                                      ['frame', 'time_s', 'seq', 'direction']].copy()
            for field in ('frame', 'time_s', 'seq'):
                chart_df[field] = pd.to_numeric(chart_df[field], errors='coerce')
            chart_df = chart_df.dropna(subset=['frame', 'time_s', 'seq'])
            if not chart_df.empty:
                chart_df['elapsed_s'] = chart_df['time_s'] - pd.to_numeric(packets_df['time_s'], errors='coerce').min()
                st.scatter_chart(chart_df, x='elapsed_s', y='seq', color='direction', height=330)
                st.markdown('**TCP sequence progression by frame number**')
                st.scatter_chart(chart_df, x='frame', y='seq', color='direction', height=330)
                st.caption('Both plots show starting TCP sequence numbers, not the full payload ranges.')
            else:
                st.info('No valid TCP payload packets to plot.')

            st.subheader(f'Stage 2 — SACK probe candidate analysis (stream {sid})')
            st.caption('Candidate probes are inferred from equal-size TCP payload packets whose starting sequence advances by one byte. This is not a validated probe-loss calculation.')
            try:
                with tempfile.TemporaryDirectory(prefix='probe_analysis_') as probe_dir:
                    probe_capture = Path(probe_dir) / upload.name
                    probe_capture.write_bytes(upload.getvalue())
                    sack_edges = extract_sack_edges(probe_capture, sid)
                probe_report = analyze_probe_candidates(raw_packets, sid, sack_edges)
                q1, q2, q3, q4 = st.columns(4)
                q1.metric('Overlapping payload candidates', probe_report['candidate_packets'])
                q2.metric('Candidate bursts', len(probe_report['bursts']))
                q3.metric('SACK response packets', probe_report['sack_response_packets'])
                q4.metric('Probe loss', 'Not determined')
                if probe_report['bursts']:
                    st.markdown('**Candidate bursts**')
                    st.dataframe(pd.DataFrame(probe_report['bursts']), hide_index=True, use_container_width=True)
                    st.markdown('**Candidate packets and SACK range evidence**')
                    st.dataframe(pd.DataFrame(probe_report['candidates']), hide_index=True,
                                 use_container_width=True, height=350)
                else:
                    st.info('No runs of three or more equal-sized payload packets with one-byte sequence increments were found.')
                st.markdown('**SACK response details (all parsed blocks)**')
                if sack_edges:
                    response_rows = [{
                        'frame': r['frame'], 'src': r['src'], 'cumulative_ack': r['cumulative_ack'],
                        'sack_blocks': ', '.join(f"[{b['left']}, {b['right_exclusive']})" for b in r['sack_blocks']),
                        'parse_complete': r['parse_complete']
                    } for r in sack_edges]
                    st.dataframe(pd.DataFrame(response_rows), hide_index=True, use_container_width=True)
                else:
                    st.info('No SACK-bearing packets observed in this TCP stream.')
                st.caption(probe_report['note'])
                st.subheader(f'Stage 3 — SACK progression and timing (stream {sid})')
                progression = analyze_sack_progression(probe_report)
                t1, t2, t3 = st.columns(3)
                t1.metric('SACK response frames', len(progression['responses']))
                t2.metric('Distinct SACK-reported bytes', progression['distinct_reported_sack_bytes'])
                interval = progression['first_candidate_to_first_sack_ms']
                t3.metric('First candidate → first SACK', f'{interval:.3f} ms' if interval is not None else 'Unknown')
                st.caption('Timing is from the first candidate payload packet to the first observed SACK response — NOT an individual probe RTT.')
                if progression['responses']:
                    st.markdown('**New vs. previously reported SACK sequence coverage**')
                    st.dataframe(pd.DataFrame(progression['responses']), hide_index=True, use_container_width=True)
                    st.markdown('**SACK blocks by response frame**')
                    blocks_df = pd.DataFrame(progression['blocks'])
                    st.dataframe(blocks_df, hide_index=True, use_container_width=True)
                    if not blocks_df.empty:
                        # Horizontal bars represent half-open TCP sequence intervals.
                        # Altair is a Streamlit dependency; no extra installation needed.
                        import altair as alt
                        blocks_df['frame_label'] = blocks_df['frame'].astype(str)
                        bars = alt.Chart(blocks_df).mark_bar(size=15).encode(
                            x=alt.X('left:Q', title='TCP relative sequence number', scale=alt.Scale(zero=False)),
                            x2='right_exclusive:Q',
                            y=alt.Y('frame_label:N', title='SACK response frame', sort=None),
                            color=alt.Color('block:N', title='Block number'),
                            tooltip=['frame:Q', 'block:Q', 'left:Q', 'right_exclusive:Q', 'length_bytes:Q']
                        ).properties(height=max(150, 55 * blocks_df['frame'].nunique()))
                        st.altair_chart(bars, use_container_width=True)
                    st.markdown('**Candidate burst and SACK response timeline**')
                    timeline_df = pd.DataFrame(progression['timeline'])
                    st.dataframe(timeline_df, hide_index=True, use_container_width=True)
                    if not timeline_df.empty:
                        st.scatter_chart(timeline_df, x='elapsed_ms', y='frame', color='direction', height=250)
                else:
                    st.info('No SACK responses observed in this stream; SACK progression cannot be calculated.')
                st.caption(progression['note'])
                st.download_button('Download Stage 3 SACK progression JSON',
                                   json.dumps(progression, indent=2),
                                   file_name=f'sack_progression_stream_{sid}.json',
                                   mime='application/json')

                st.download_button('Download probe candidate JSON', json.dumps(probe_report, indent=2),
                                   file_name=f'probe_candidates_stream_{sid}.json', mime='application/json')
            except Exception as exc:
                st.error(f'Stage 2 analysis failed: {exc}')

            if st.button(f'Prepare stream {sid} PCAP for download'):
                try:
                    with tempfile.TemporaryDirectory(prefix='stream_export_') as export_dir:
                        original = Path(export_dir) / 'original.pcap'
                        output = Path(export_dir) / f'stream_{sid}.pcapng'
                        original.write_bytes(upload.getvalue())
                        cmd = ['tshark', '-r', str(original), '-Y', f'tcp.stream == {int(sid)}', '-w', str(output)]
                        result = subprocess.run(cmd, capture_output=True, text=True)
                        if result.returncode != 0:
                            raise RuntimeError(result.stderr.strip() or 'TShark export failed')
                        st.session_state['stream_export'] = {'sid': sid, 'bytes': output.read_bytes()}
                except Exception as exc:
                    st.error(f'PCAP export failed: {exc}')
            export = st.session_state.get('stream_export')
            if export and export['sid'] == sid:
                st.download_button('Download selected TCP stream PCAP', export['bytes'],
                                   file_name=f'stream_{sid}.pcapng', mime='application/octet-stream')
                st.caption('The exported PCAP contains only this stream. Wireshark may renumber streams and frames when opened separately.')


with tab_mtu:
    st.subheader('Stage 4 — TCP connection lifecycle and MTU evidence')
    st.caption('Connection outcomes describe captured packets only; they do not prove final socket state.')
    life = stage4['streams']
    if life:
        life_df = pd.DataFrame([{k:v for k,v in entry.items() if k!='events' and k!='rst_senders'} | {'rst_senders': ', '.join(entry['rst_senders'])} for entry in life])
        st.dataframe(life_df, hide_index=True, use_container_width=True, height=330)
    mtu = stage4['mtu']
    c1,c2,c3,c4=st.columns(4)
    lab_matches_capture = (m.get('source_ip') == LAB['source_ip'] and m.get('target_ip') == LAB['destination_ip'])
    c1.metric('Agent interface MTU', f"{LAB['source_interface_mtu']} B (external lab)" if lab_matches_capture else 'Unknown')
    c2.metric('Target interface MTU', 'Unknown')
    c3.metric('Confirmed path MTU', 'Unknown')
    c4.metric('Largest captured DF Echo Request', f"{mtu['largest_df_echo_ip_packet_bytes']} B" if mtu['largest_df_echo_ip_packet_bytes'] else 'None')
    st.caption('A captured DF Echo Request does not establish delivery. MSS+40 is a conventional IPv4 comparison, not actual MTU.')
    with st.expander('TCP MSS advertisements (SYN/SYN-ACK)'):
        st.dataframe(pd.DataFrame(mtu['mss_observations']), hide_index=True, use_container_width=True)
    with st.expander('DF Echo Requests and ICMP Fragmentation Needed'):
        st.markdown('**Captured DF Echo Requests**')
        st.dataframe(pd.DataFrame(mtu['df_echo_requests']), hide_index=True, use_container_width=True)
        st.markdown('**Captured ICMP Type 3 Code 4 messages**')
        if mtu['fragmentation_needed_messages']:
            st.dataframe(pd.DataFrame(mtu['fragmentation_needed_messages']), hide_index=True, use_container_width=True)
        else:
            st.info('No ICMP Fragmentation Needed messages observed. This does not prove the path supports 1500 bytes.')
    st.caption(' '.join(mtu['notes']))
    st.markdown('#### Stage 4 — External MTU validation (manual lab measurements)')
    st.caption('These tests were performed after the capture and are NOT derived from the uploaded PCAP. Bundled lab path: 192.168.8.77 → 142.251.39.142.')
    if not lab_matches_capture:
        st.error('Bundled MTU measurements do not match this capture’s identified source/destination. External evidence is shown as an unrelated example only.')
    with st.expander('Measurement source and settings', expanded=False):
        st.json(LAB)
        st.caption('Edit mtu_validation.py to enter measurements from another lab. Do not reuse this evidence for a different capture or path.')
    validation = summarize(PROBES)
    v1,v2,v3,v4 = st.columns(4)
    v1.metric('Largest successful DF Echo', f"{validation['largest_successful_probe_bytes']:,} B")
    v2.metric('Smallest unanswered DF Echo', f"{validation['smallest_unanswered_probe_bytes']:,} B")
    v3.metric('Tracepath PMTU report', f"{LAB['tracepath_reported_pmtu']:,} B")
    v4.metric('Confirmed end-to-end PMTU', 'Unknown')
    st.warning('Observed ICMP response boundary is NOT a confirmed path MTU. Tracepath did not reach the target; no ICMP Fragmentation Needed evidence established a lower PMTU.')
    probe_df = pd.DataFrame(validation['probes'])
    aggregated = probe_df.groupby('ipv4_packet_bytes', as_index=False)[['sent','received','unanswered']].sum()
    aggregated['reply_rate_pct'] = (aggregated['received'] / aggregated['sent'] * 100).round(1)
    st.markdown('**DF Echo reply rate by IPv4 packet size**')
    # Plot tested sizes as discrete points, not a misleading interpolated line.
    plot_df = aggregated.copy()
    plot_df['result'] = plot_df['received'].apply(lambda n: 'Replies received' if n else 'No replies')
    base = alt.Chart(plot_df).encode(
        x=alt.X('ipv4_packet_bytes:Q', title='Total IPv4 packet size (bytes)',
                scale=alt.Scale(domain=[1325, 1510]), axis=alt.Axis(tickCount=12)),
        y=alt.Y('reply_rate_pct:Q', title='ICMP Echo reply rate (%)', scale=alt.Scale(domain=[-5, 105])),
        tooltip=[alt.Tooltip('ipv4_packet_bytes:Q', title='IPv4 size (B)'),
                 alt.Tooltip('sent:Q'), alt.Tooltip('received:Q'),
                 alt.Tooltip('reply_rate_pct:Q', title='Reply rate (%)')])
    points = base.mark_circle(size=125).encode(
        color=alt.Color('result:N', title='Observation',
                        scale=alt.Scale(domain=['Replies received', 'No replies'], range=['#22a06b','#e05252'])))
    boundary = alt.Chart(pd.DataFrame({'x': [1434.5]})).mark_rule(
        color='#e0aa36', strokeDash=[6, 5], strokeWidth=2).encode(x='x:Q')
    st.altair_chart(points + boundary, use_container_width=True)
    st.caption('Dashed line marks the observed 1,434/1,435 B ICMP reply boundary; it is not a confirmed PMTU.')
    st.dataframe(aggregated, hide_index=True, use_container_width=True)
    st.caption('Successful replies verify an Echo request/reply exchange for that packet size, not which direction limits larger packets. No-reply does not by itself prove fragmentation or loss in the network.')
    with st.expander('Original individual test runs'):
        st.dataframe(probe_df, hide_index=True, use_container_width=True)
    st.download_button('Download Stage 4 JSON (PCAP + separate lab evidence)', json.dumps({'pcap_stage4':stage4,'external_mtu_validation':validation}, indent=2), file_name='connection_mtu_report_with_validation.json', mime='application/json')


    if streams:
        st.markdown(f'**Stage 4 — Connection events for stream {sid}**')
        selected_life = next((item for item in life if item['stream'] == sid), None)
        if selected_life:
            a4,b4,c4,d4=st.columns(4)
            a4.metric('Connection outcome', selected_life['outcome'])
            b4.metric('First FIN sender', selected_life['first_fin_sender'] or 'None observed')
            c4.metric('RST packets', selected_life['rst_packets'])
            d4.metric('Repeated FIN signatures', selected_life['repeated_fin_signatures'])
            if selected_life['events']:
                st.dataframe(pd.DataFrame(selected_life['events']), hide_index=True, use_container_width=True)
                timeline_life=pd.DataFrame(selected_life['events'])
                if timeline_life['time_epoch'].notna().any():
                    timeline_life['elapsed_ms']=(timeline_life['time_epoch']-timeline_life['time_epoch'].min())*1000
                    st.scatter_chart(timeline_life, x='elapsed_ms', y='frame', color='event', height=240)

with tab_insights:
    st.subheader('Stage 5 — Automated troubleshooting insights')
    st.caption('Deterministic rules based on observed packets and separately labeled lab evidence. These are diagnostic leads, not verified root causes.')
    insights = build_insights(report, stage4, validation if lab_matches_capture else None)
    for finding in insights:
        with st.expander(f"[{finding['severity']}] {finding['title']}", expanded=finding['severity'] == 'Review'):
            st.markdown(f"**Category:** {finding['category']}  |  **Confidence:** {finding['confidence']}")
            st.write(finding['explanation'])
            st.markdown('**Evidence**')
            for item in finding['evidence']:
                st.write('• ' + str(item))
            st.markdown('**Next step:** ' + finding['next_step'])
    st.download_button('Download Stage 5 insights JSON',
        json.dumps({'findings': insights, 'external_lab_evidence_included': lab_matches_capture}, indent=2),
        file_name='troubleshooting_insights.json', mime='application/json')


with tab_overview:
    if report['dns']:
        st.subheader('DNS observations')
        st.dataframe(pd.DataFrame(report['dns']),hide_index=True,use_container_width=True)
    st.warning('TCP retransmission labels in probe-like streams are not reliable packet-loss estimates. TTL and MSS also require context.')
