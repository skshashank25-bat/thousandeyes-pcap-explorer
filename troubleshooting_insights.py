"""Deterministic, evidence-linked troubleshooting findings; no speculative loss estimates."""
def build_insights(report, stage4, validation=None):
    findings = []
    def add(category, title, severity, confidence, explanation, evidence, next_step):
        findings.append(dict(category=category, title=title, severity=severity,
                             confidence=confidence, explanation=explanation,
                             evidence=evidence, next_step=next_step))
    streams = report.get("streams", [])
    lifecycle = stage4.get("streams", [])
    measurement = report.get("measurement", {})
    mtu = stage4.get("mtu", {})

    probe_streams = [s for s in streams if s.get("probe_like_overlap")]
    if probe_streams:
        details = []
        for s in probe_streams[:8]:
            overlaps = s.get("sequence_overlap_evidence", [])
            examples = [str(e["frame"]) for e in overlaps[:3] if e.get("frame") is not None]
            details.append(f"stream {s['stream']}: {len(overlaps)} overlap records"
                           + (f" (example frames {', '.join(examples)})" if examples else ""))
        add("TCP / SACK", "Overlapping TCP payload sequences detected", "Informational",
            "High (overlap observed); medium (probe interpretation)",
            "Several payload segments reuse overlapping TCP sequence ranges. In synthetic "
            "ThousandEyes tests, TShark may classify these as retransmissions even when "
            "they are deliberate probes. Do not convert these flags into packet-loss percentages.",
            details, "Inspect Stage 2/3 candidate bursts and SACK blocks for the selected streams.")

    flagged = [s for s in streams if s.get("retransmission_flags", 0)]
    if flagged:
        add("TCP", "TShark retransmission classifications present", "Informational",
            "High (dissector labels); low (actual loss inference)",
            f"{sum(s.get('retransmission_flags',0) for s in flagged)} retransmission labels "
            f"across {len(flagged)} streams. Labels alone cannot establish actual packet loss.",
            [f"stream {s['stream']}: {s.get('retransmission_flags',0)} flags; "
             f"probe-like={s.get('probe_like_overlap',False)}" for s in flagged[:8]],
            "Correlate sequence ranges, ACK/SACK coverage, capture direction, and timing.")

    resets = [s for s in lifecycle if s.get("rst_packets", 0)]
    if resets:
        add("TCP lifecycle", "TCP reset packets observed", "Review", "High (RST observed)",
            f"RST flags were captured in {len(resets)} streams. A reset is a connection event; "
            "its cause cannot be established from the flag alone.",
            [f"stream {s['stream']}: {s['rst_packets']} RST; "
             f"outcome={s.get('outcome','unknown')}" for s in resets[:8]],
            "Open Stage 4 connection events and inspect RST direction and surrounding frames.")

    repeated_fin = [s for s in lifecycle if s.get("repeated_fin_signatures", 0)]
    if repeated_fin:
        add("TCP lifecycle", "Repeated FIN signatures observed", "Review",
            "High (repeated signatures); low (root cause)",
            "Repeated FIN signatures may indicate an unacknowledged close or a capture/test artifact.",
            [f"stream {s['stream']}: {s['repeated_fin_signatures']} repeated FIN signatures"
             for s in repeated_fin[:8]],
            "Inspect FIN sequence numbers and ACKs before concluding that FINs were lost.")

    sacks = measurement.get("sack_response_packets", 0)
    if probe_streams:
        add("TCP / SACK", "SACK responses and probe overlap need separate interpretation",
            "Informational", "High (capture counts)",
            f"{sacks} SACK-bearing responses counted for the identified reverse direction. "
            "SACK coverage is byte-range evidence, not a count of successfully delivered probes.",
            [f"SACK-bearing reverse-direction packets: {sacks}"],
            "Use Stage 3 SACK progression to inspect newly acknowledged byte ranges.")

    frag = mtu.get("fragmentation_needed_messages", [])
    if frag:
        add("MTU", "ICMP Fragmentation Needed messages captured", "Review", "High",
            "The capture includes ICMP Type 3 Code 4 messages, which can support PMTU investigation.",
            [f"{len(frag)} fragmentation-needed messages observed"],
            "Inspect the router address, reported next-hop MTU, and quoted original packet.")
    else:
        add("MTU", "No ICMP Fragmentation Needed observed", "Informational", "High (in capture)",
            "No ICMP Type 3 Code 4 messages were observed in the analyzed capture. "
            "This does not prove there is no MTU limitation.",
            ["Stage 4: zero fragmentation-needed messages"],
            "Capture ICMP during a controlled DF probe; intermediate routers may originate errors.")

    if validation:
        a = validation.get("largest_successful_probe_bytes")
        b = validation.get("smallest_unanswered_probe_bytes")
        add("MTU / external lab", "Sharp ICMP Echo reply boundary in separate lab tests",
            "Review", "High (reported replies); unconfirmed PMTU",
            f"External tests received replies at {a} B but none at {b} B. "
            "This is an ICMP request/reply response boundary, NOT a proven forward or reverse PMTU. "
            "Measurements were taken after the uploaded capture.",
            [f"largest successful DF Echo: {a} B",
             f"smallest unanswered DF Echo: {b} B",
             f"tracepath reached destination: {validation['lab'].get('tracepath_reached_destination')}"],
            "Capture both directions and ICMP errors during a repeat test; consider a TCP-based PMTU test.")

    if not findings:
        add("General", "No rules triggered", "Informational", "Low",
            "No predefined troubleshooting patterns were detected. This does not mean the path is healthy.",
            ["No rule matched the current analysis"], "Review packet-level data and test context.")
    return findings
