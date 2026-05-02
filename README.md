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
<summary><strong>🐍 Download Python</strong></summary>

https://www.python.org/downloads/

</details>

---

### Install Scapy

<details>
<summary><strong> macOS / 🐧 Linux</strong></summary>

```bash
pip3 install scapy
```

</details>

<details>
<summary><strong>🪟 Windows</strong></summary>

```bash
pip install scapy
```

</details>

---

### Run the tool

<details>
<summary><strong> macOS / 🐧 Linux</strong></summary>

```bash
python3 basic-network-tool.py <your_file_path>.pcap
```

</details>

<details>
<summary><strong>🪟 Windows</strong></summary>

```bash
python basic-network-tool.py <your_file_path>.pcap
```

</details>

---

## Notes
- Replace `<your_file_path>.pcap` with your actual file
- You can place the `.pcap` file in the same directory or use a full path
- This is an early version of the tool and will be improved over time
