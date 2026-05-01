# Basic Network Log Analyzer
A simple tool to analyze `.pcap` files using Scapy.

## Features
- Count the number of requests per IP
- Detect suspicious ports
- Basic spam detection based on request volume
- Log analysis results to `log.txt`

## Usage

### Requirements
- Python 3.x
- Scapy

<details>
<summary><strong> macOS / 🐧 Linux</strong></summary>

```bash
pip3 install scapy
python3 basic-network-tool.py
```

</details>

<details>
<summary><strong>🪟 Windows</strong></summary>

```bash
pip install scapy
python basic-network-tool.py
```

</details>

## Notes
- Place your `.pcap` file in the same directory as the script  
  or modify the filename inside the code.
- This is an early version of the tool and will be improved over time.
