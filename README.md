# Basic Network Log Analyzer
A simple tool to analyze `.pcap` files using scapy

## Features
- Count number of requests per IP
- Detect suspicious ports
- Basic spam detect (based on requests volume)
- Log analysis results in `log.txt` file

## Usage

### Requirements
- Python 3.x
- Scapy

<details>
<summary><strong>🍎 macOS / 🐧Linux</strong></summary>

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

### Notes
- Place your `.pcap` file in the same directory as the script  
  or modify the filename inside the code.
  
## Notes
- This is the early version, this tool will be improved later.
