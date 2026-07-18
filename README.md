# DPI Engine — Deep Packet Inspection System

A C++17 packet inspection engine that reads PCAP captures, classifies traffic by application (YouTube, Facebook, etc.) using TLS SNI / HTTP Host extraction, applies configurable blocking rules, and writes filtered PCAP output with a full traffic report.

Includes both a single-threaded reference implementation and a multi-threaded, consistent-hashing pipeline for high-throughput processing.

```
Wireshark Capture (input.pcap) → DPI Engine → Filtered PCAP + Report
                                     │
                                     ├── Parses Ethernet/IP/TCP/UDP headers
                                     ├── Extracts SNI/Host from TLS & HTTP
                                     ├── Classifies traffic by application
                                     ├── Applies IP/App/Domain blocking rules
                                     └── Forwards or drops per-flow
```

## Features

- **PCAP reading/writing** — parses the standard libpcap file format (global header + per-packet records)
- **Protocol parsing** — Ethernet, IPv4, TCP, and UDP header decoding with correct network-byte-order handling
- **SNI extraction** — parses TLS Client Hello handshakes to recover the plaintext domain name from the SNI extension, even over HTTPS
- **HTTP Host extraction** — recovers the `Host:` header from plaintext HTTP requests
- **Application classification** — maps extracted domains to app types (YouTube, Facebook, Google, etc.)
- **Flow tracking** — packets are grouped into connections via the 5-tuple (src IP, dst IP, src port, dst port, protocol); a flow is classified once its SNI is seen, and the decision applies to all subsequent packets in that flow
- **Rule-based blocking** — block by source IP, application type, or domain substring
- **Multi-threaded pipeline** — reader → load balancers → fast paths → output writer, with consistent hashing so all packets of a flow are handled by the same worker thread
- **Reporting** — packet counts, forwarded/dropped totals, per-thread work distribution, and an application breakdown with detected domains

## Architecture

### Single-threaded pipeline (`src/main_working.cpp`)

Read packet → parse headers → look up/create flow (5-tuple) → extract SNI (if HTTPS/HTTP) → classify app → check rules → forward or drop → repeat → generate report.

### Multi-threaded pipeline (`src/dpi_mt.cpp`)

```
Reader Thread → hash(5-tuple) → LB0 / LB1 (Load Balancers)
                                     │
                          hash(5-tuple) → FP0 / FP1 / FP2 / FP3 (Fast Paths)
                                     │
                              Output Queue → Output Writer Thread
```

- **Reader Thread** reads the PCAP and dispatches packets to a Load Balancer keyed by `hash(5-tuple) % num_lbs`.
- **Load Balancer (LB) threads** forward packets to a Fast Path keyed by `hash(5-tuple) % num_fps`.
- **Fast Path (FP) threads** own their own flow table, perform SNI extraction/classification, apply blocking rules, and push forwarded packets to the output queue.
- **Output Writer Thread** writes forwarded packets to the output PCAP.
- Consistent hashing guarantees every packet in a given connection always lands on the same FP, so per-flow state stays correct.
- Coordination between threads uses a mutex + condition-variable thread-safe queue (`thread_safe_queue.h`).

## Project Structure

```
packet_analyzer/
├── include/
│   ├── pcap_reader.h          # PCAP file reading
│   ├── packet_parser.h        # Network protocol parsing
│   ├── sni_extractor.h        # TLS/HTTP inspection
│   ├── types.h                # FiveTuple, AppType, Flow, etc.
│   ├── rule_manager.h         # Blocking rules (multi-threaded version)
│   ├── connection_tracker.h   # Flow tracking (multi-threaded version)
│   ├── load_balancer.h        # LB thread (multi-threaded version)
│   ├── fast_path.h            # FP thread (multi-threaded version)
│   ├── thread_safe_queue.h    # Thread-safe queue
│   └── dpi_engine.h           # Main orchestrator
├── src/
│   ├── pcap_reader.cpp
│   ├── packet_parser.cpp
│   ├── sni_extractor.cpp
│   ├── types.cpp
│   ├── main_working.cpp       # Single-threaded entry point
│   ├── dpi_mt.cpp             # Multi-threaded entry point
│   └── ...
├── generate_test_pcap.py      # Generates sample traffic for testing
├── test_dpi.pcap              # Sample capture
└── README.md
```

## How SNI Extraction Works

TLS encrypts application data, but the very first message of the handshake — the **Client Hello** — is sent in plaintext and contains the destination hostname in its SNI extension. The engine parses this structure directly:

1. Confirms the record is a TLS Handshake (`0x16`) containing a Client Hello (`0x01`)
2. Skips over the version, random bytes, session ID, cipher suites, and compression methods
3. Walks the extensions list looking for extension type `0x0000` (Server Name Indication)
4. Reads the hostname length and value out of the SNI extension

Because this happens before encryption is established, the domain (e.g. `www.youtube.com`) is visible even though everything after the handshake is encrypted. Plaintext HTTP is handled similarly by scanning for the `Host:` header.

## Blocking Model

Rules are evaluated in order — IP, then app, then domain — and act at the **flow** level, not the packet level:

```
Source IP blacklisted?  → drop
App type blacklisted?   → drop
SNI matches domain rule (substring)? → drop
otherwise                → forward
```

A connection's early packets (SYN, SYN-ACK, ACK) carry no SNI and are forwarded by default. Once the Client Hello reveals the app/domain, the flow is marked blocked (or allowed), and that decision is applied to every subsequent packet in the same connection.

## Building

Requires a C++17 compiler (g++ or clang++) and no external libraries.

**Single-threaded version:**

```bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

**Multi-threaded version:**

```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

## Usage

```bash
./dpi_engine test_dpi.pcap output.pcap
```

**With blocking rules:**

```bash
./dpi_engine test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

**Configuring thread pool size (multi-threaded version only):**

```bash
./dpi_engine input.pcap output.pcap --lbs 4 --fps 4
# 4 load balancers × 4 fast paths = 16 processing threads
```

**Generating test data:**

```bash
python3 generate_test_pcap.py
# produces test_dpi.pcap with a mix of sample traffic
```

## Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                              ║
║ Total Bytes:                5738                              ║
║ TCP Packets:                  73                              ║
║ UDP Packets:                   4                              ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    69                              ║
║ Dropped:                       8                              ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                     ║
║ Unknown              16  20.8% ####                           ║
║ YouTube               4   5.2% # (BLOCKED)                    ║
║ DNS                   4   5.2% #                              ║
║ Facebook              3   3.9%                                ║
╚══════════════════════════════════════════════════════════════╝
```

| Field                 | Meaning                                                      |
| --------------------- | ------------------------------------------------------------ |
| Total Packets         | Packets read from the input capture                          |
| Forwarded             | Packets written to the output capture                        |
| Dropped               | Packets blocked and excluded from output                     |
| Thread Statistics     | Work distribution across LB/FP threads (multi-threaded only) |
| Application Breakdown | Traffic classified by app type, with percentages             |
| Detected Domains/SNIs | Actual hostnames recovered from the traffic                  |

## Roadmap / Ideas for Extension

- Additional app signatures (e.g. Twitch) in `sniToAppType`
- Bandwidth throttling as an alternative to hard drops
- Live statistics dashboard on a separate thread
- QUIC/HTTP3 support (SNI lives in the encrypted Initial packet, requiring different handling)
- Persistent rule sets loaded from a config file on startup

## License

Add your preferred license here (e.g. MIT).
