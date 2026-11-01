# ThousandEyes PCAP Explorer

A Python and Streamlit-based PCAP analysis dashboard for network troubleshooting, with a focus on ThousandEyes packet captures.

## Features

- Stage 1: TCP stream inspection and packet-level visualization
- Stage 2: SACK probe candidate detection
- Stage 3: SACK progression and timing analysis
- Stage 4: TCP connection lifecycle and MTU evidence
- Stage 5: Automated troubleshooting insights
- Interactive dashboard with organized tabs
- JSON report exports and TCP stream PCAP export

## Technology Stack

- Python
- Streamlit
- TShark / Wireshark
- Pandas
- Altair

## Requirements

- Python 3
- TShark installed and available in PATH

## Installation

Clone the repository and enter the project directory.

Create a virtual environment:

    python3 -m venv .venv
    source .venv/bin/activate

Install dependencies:

    pip install -r requirements.txt

## Running the Dashboard

    streamlit run dashboard.py

Open http://localhost:8501 and upload a PCAP or PCAPNG file.

## Important Notes

- Retransmission labels do not always indicate actual packet loss.
- Overlapping TCP payloads may represent synthetic probe traffic.
- SACK evidence must be interpreted in the context of TCP sequence numbers.
- An ICMP reply-size boundary does not establish a confirmed path MTU.
- Automated troubleshooting findings are diagnostic leads, not verified root causes.
- External MTU validation measurements are separate from captured PCAP evidence.

## Future Enhancements

- AI-assisted packet analysis
- Natural-language troubleshooting questions
- Enhanced ThousandEyes test correlation

## Disclaimer

This is an independent troubleshooting and learning project, not an official Cisco ThousandEyes product.
