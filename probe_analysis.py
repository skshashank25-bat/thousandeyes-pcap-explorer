"""Conservative, evidence-first SACK probe candidate inspection.

Requires tshark, used only on a user-supplied local capture. No loss calculation.
"""
import subprocess


def _int(value, default=None):
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return default


def _float(value, default=None):
    try:
        return float(str(value).strip())
    except (ValueError, TypeError):
        return default


def _bool(value):
    return str(value).strip().lower() in ('true', '1')


def _numbers(value):
    values = []
    for item in str(value or '').split(','):
        n = _int(item)
        if n is not None:
            values.append(n)
    return values


def extract_sack_edges(capture, sid):
    """Extract ALL SACK left/right edges without the main analyzer's first-only setting."""
    command = [
        'tshark', '-n', '-r', str(capture), '-Y', f'tcp.stream == {int(sid)} && tcp.options.sack_le',
        '-T', 'fields', '-E', 'separator=/t', '-E', 'occurrence=a',
        '-E', 'aggregator=,', '-E', 'quote=n',
        '-e', 'frame.number', '-e', 'frame.time_epoch',
        '-e', 'ip.src', '-e', 'tcp.ack',
        '-e', 'tcp.options.sack_le', '-e', 'tcp.options.sack_re'
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'TShark SACK extraction failed')
    responses = []
    for line in result.stdout.splitlines():
        cells = (line.split('\t') + [''] * 6)[:6]
        frame, time, src, ack, lefts, rights = cells
        left_values, right_values = _numbers(lefts), _numbers(rights)
        blocks = [{'left': left, 'right_exclusive': right}
                  for left, right in zip(left_values, right_values) if right > left]
        responses.append({
            'frame': _int(frame), 'time_epoch': _float(time), 'src': src,
            'cumulative_ack': _int(ack), 'sack_blocks': blocks,
            'left_edges': left_values, 'right_edges': right_values,
            'parse_complete': len(left_values) == len(right_values),
        })
    return responses


def analyze_probe_candidates(raw_packets, sid, sack_responses):
    """Find overlapping equal-size TCP payload runs; annotate SACK coverage, not probe success."""
    stream = [p for p in raw_packets if p.get('tcp.stream') == str(sid)]
    source = next((p.get('ip.src') for p in stream
                   if _bool(p.get('tcp.flags.syn')) and not _bool(p.get('tcp.flags.ack'))), None)
    if not source:
        return {'candidates': [], 'bursts': [], 'responses': sack_responses,
                'note': 'No initiating SYN observed: source direction is unknown.'}
    payload = []
    for p in stream:
        if p.get('ip.src') != source:
            continue
        size, seq = _int(p.get('tcp.len'), 0), _int(p.get('tcp.seq'))
        if size <= 0 or seq is None:
            continue
        payload.append({
            'frame': _int(p.get('frame.number')),
            'time_epoch': _float(p.get('frame.time_epoch')),
            'seq_start': seq, 'seq_end_exclusive': seq + size,
            'payload_bytes': size,
        })
    payload.sort(key=lambda p: p['frame'])

    # Identify contiguous runs with same payload length and exactly one-byte seq advancement.
    runs = []
    current = []
    for p in payload:
        if current and (p['payload_bytes'] != current[-1]['payload_bytes'] or
                        p['seq_start'] - current[-1]['seq_start'] != 1):
            if len(current) >= 3:
                runs.append(current)
            current = []
        current.append(p)
    if len(current) >= 3:
        runs.append(current)

    candidates, bursts = [], []
    for idx, run in enumerate(runs, 1):
        bursts.append({
            'burst': idx, 'first_frame': run[0]['frame'], 'last_frame': run[-1]['frame'],
            'candidate_packets': len(run), 'payload_bytes_each': run[0]['payload_bytes'],
            'first_seq': run[0]['seq_start'], 'last_seq': run[-1]['seq_start'],
            'duration_ms': round((run[-1]['time_epoch'] - run[0]['time_epoch']) * 1000, 3)
                           if run[0]['time_epoch'] is not None and run[-1]['time_epoch'] is not None else None,
        })
        for p in run:
            # A later SACK range that intersects a payload does NOT uniquely acknowledge that probe.
            later = [r for r in sack_responses
                     if r['frame'] is not None and p['frame'] is not None and r['frame'] > p['frame']
                     and r['src'] != source and any(
                         b['left'] < p['seq_end_exclusive'] and b['right_exclusive'] > p['seq_start']
                         for b in r['sack_blocks'])]
            candidates.append({
                'burst': idx, **p,
                'later_sack_overlap': bool(later),
                'first_overlapping_sack_frame': later[0]['frame'] if later else None,
                'response_status': 'SACK range overlaps; individual probe unverified' if later
                                   else 'No overlapping SACK observed (not proof of loss)',
            })
    return {
        'source_ip': source, 'candidates': candidates, 'bursts': bursts,
        'responses': sack_responses,
        'total_payload_packets': len(payload),
        'candidate_packets': len(candidates),
        'sack_response_packets': len(sack_responses),
        'note': 'Heuristic only. Overlap is not unique probe-to-response matching; '
                'no RTT or packet-loss percentage is calculated.'
    }
