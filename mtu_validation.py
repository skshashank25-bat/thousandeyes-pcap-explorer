"""External host/ICMP observations. These are not inferred from an uploaded PCAP."""
from datetime import date

# Manually recorded lab evidence for this particular source/destination.
LAB = {
    'source_ip': '192.168.8.77',
    'source_interface': 'eth0',
    'source_interface_mtu': 1500,
    'gateway': '192.168.8.1',
    'destination_ip': '142.251.39.142',
    'tracepath_reported_pmtu': 1500,
    'tracepath_reached_destination': False,
    'confirmed_path_mtu': None,
    'target_interface_mtu': None,
}
# Total IPv4 packet size = ping -s payload + 28 (20-byte IPv4 + 8-byte ICMP).
# Each entry corresponds to an actual ping run supplied by the operator.
PROBES = [
    (1334,4,4), (1400,3,3), (1420,3,3), (1430,3,3),
    (1432,5,5), (1432,5,5), (1433,5,5), (1434,5,5),
    (1435,5,0), (1436,5,0), (1437,5,0), (1438,5,0),
    (1440,3,0), (1450,3,0), (1480,3,0), (1500,4,0),
]

def summarize(probes):
    rows = [{'ipv4_packet_bytes': size, 'icmp_payload_bytes': size-28,
             'sent': sent, 'received': received, 'unanswered': sent-received,
             'reply_rate_pct': round(100*received/sent,1) if sent else None,
             'observation': 'Replies received' if received == sent else ('No replies' if received == 0 else 'Partial replies')}
            for size,sent,received in probes]
    successful = [r['ipv4_packet_bytes'] for r in rows if r['received'] > 0]
    unanswered = [r['ipv4_packet_bytes'] for r in rows if r['received'] == 0]
    return {'lab': LAB.copy(), 'probes': rows,
            'largest_successful_probe_bytes': max(successful) if successful else None,
            'smallest_unanswered_probe_bytes': min(unanswered) if unanswered else None,
            'interpretation': ('Observed size-dependent ICMP Echo response cutoff; '
                'not proof of forward/reverse PMTU. Missing replies may result from filtering, '
                'silent MTU drops, or return-path behavior. Tracepath did not reach destination.')}
