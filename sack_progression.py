"""SACK range progression for exploratory packet-capture analysis.

All ranges are half-open [left, right). Coverage means reported SACK sequence
space, not uniquely delivered probe packets, RTT, or packet-loss measurement.
"""


def merge_ranges(ranges):
    valid = sorted((int(a), int(b)) for a, b in ranges if a is not None and b is not None and int(b) > int(a))
    merged = []
    for left, right in valid:
        if merged and left <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], right))
        else:
            merged.append((left, right))
    return merged


def subtract_ranges(current, previously):
    """Return portions of current half-open ranges absent from previous union."""
    result = []
    for left, right in merge_ranges(current):
        pos = left
        for a, b in merge_ranges(previously):
            if b <= pos:
                continue
            if a >= right:
                break
            if a > pos:
                result.append((pos, min(a, right)))
            pos = max(pos, b)
            if pos >= right:
                break
        if pos < right:
            result.append((pos, right))
    return merge_ranges(result)


def range_size(ranges):
    return sum(b - a for a, b in merge_ranges(ranges))


def analyze_sack_progression(probe_report):
    responses = sorted(probe_report.get('responses', []), key=lambda r: (r.get('frame') is None, r.get('frame') or 0))
    bursts = probe_report.get('bursts', [])
    candidates = probe_report.get('candidates', [])
    first_burst_frame = min((b['first_frame'] for b in bursts), default=None)
    first_burst_time = min((p['time_epoch'] for p in candidates if p.get('time_epoch') is not None), default=None)
    seen = []
    rows, block_rows, timeline = [], [], []
    if first_burst_time is not None:
        timeline.append({'event': 'First candidate payload', 'frame': first_burst_frame,
                         'elapsed_ms': 0.0, 'direction': 'Agent → target'})
    for r in responses:
        current = merge_ranges((b['left'], b['right_exclusive']) for b in r.get('sack_blocks', []))
        new = subtract_ranges(current, seen)
        repeated = range_size(current) - range_size(new)
        seen = merge_ranges(seen + current)
        frame = r.get('frame')
        time = r.get('time_epoch')
        delta = round((time - first_burst_time) * 1000, 3) if time is not None and first_burst_time is not None else None
        rows.append({'frame': frame, 'cumulative_ack': r.get('cumulative_ack'),
                     'sack_blocks': len(r.get('sack_blocks', [])),
                     'current_sack_bytes': range_size(current),
                     'newly_reported_bytes': range_size(new),
                     'previously_reported_bytes': repeated,
                     'cumulative_distinct_sack_bytes': range_size(seen),
                     'ms_since_first_candidate': delta,
                     'parse_complete': r.get('parse_complete', False)})
        for idx, block in enumerate(r.get('sack_blocks', []), 1):
            block_rows.append({'frame': frame, 'block': idx,
                               'left': block['left'], 'right_exclusive': block['right_exclusive'],
                               'length_bytes': block['right_exclusive'] - block['left']})
        if delta is not None:
            timeline.append({'event': f'SACK response {frame}', 'frame': frame,
                             'elapsed_ms': delta, 'direction': 'Target → agent'})
    return {'responses': rows, 'blocks': block_rows, 'timeline': timeline,
            'distinct_reported_sack_bytes': range_size(seen),
            'first_candidate_to_first_sack_ms': next((r['ms_since_first_candidate'] for r in rows if r['ms_since_first_candidate'] is not None), None),
            'note': 'SACK coverage is the union of receiver-reported TCP sequence ranges. Newly reported bytes are relative to earlier observed SACK responses, not unique probes. The first-candidate-to-SACK interval is NOT individual probe RTT; capture gaps and ACK aggregation can affect interpretation. No packet-loss percentage is inferred.'}
