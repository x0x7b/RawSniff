
# 🕷️ RawSniff

[![Go Version](https://img.shields.io/badge/Go-1.18+-blue.svg)](https://golang.org/)
[![TUI Powered](https://img.shields.io/badge/TUI-tview-yellow.svg)](https://github.com/rivo/tview)
[![Packet Capture](https://img.shields.io/badge/Capture-gopacket-orange)](https://github.com/google/gopacket)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Platform](https://img.shields.io/badge/Platform-linux%20%7C%20windows-lightgrey)
![GitHub stars](https://img.shields.io/github/stars/x0x7b/RawSniff?style=social)

**RawSniff** is a sleek and powerful terminal-based network packet sniffer written in Go. It leverages `gopacket` for low-level packet inspection and `tview` for a highly interactive terminal UI. Whether you're into networking, cybersec, or just love packet porn — this tool is for you.

---

## 🚀 Features

- 📡 **Interface selection** before capture start
- 🔎 **BPF filter** support — apply filters on the fly
- 🖥️ **Live TUI** using `tview`, clean and responsive
- 📦 Captures **TCP / UDP / ICMP** traffic with details
- 🧠 Intelligent detection of **HTTP payloads**
- 💾 **Save to .pcap** files with custom filename option (`-set-filename`)
- ⏸️ **Pause/Resume** capturing at any time
- 📊 Live **statistics** and **top IP rating**
- 🖱️ **Mouse support** out of the box

---

## 📸 Screenshots

<img width="1920" height="1040" alt="image" src="https://github.com/user-attachments/assets/bbc6bc83-dc68-47a0-acaa-bcec6bc0b5e8" />


---

## 🛠️ Build & Run

### Prerequisites

- Go 1.18+
- libpcap (`WinPcap` or `npcap` on Windows)

### Installation

```bash
git clone https://github.com/yourusername/RawSniff.git
cd RawSniff
go build -o rawsniff
```

### Usage

```bash
sudo ./rawsniff
```

> ⚠️ Root privileges are required for packet capturing on most systems.

---

## 🧠 Hotkeys

| Key           | Action                |
|---------------|------------------------|
| `Ctrl+C`      | Quit                   |
| `Ctrl+D`      | Pause/Resume capture   |
| `Ctrl+P`      | Focus packet list      |
| `Shift+Tab`   | Cycle focus            |

---

## 📂 Save Captured Packets

Press the `Save Packets` button or run with:

```bash
-set-filename custom_name.pcap
```

Captured packets will be saved in `.pcap` format (Wireshark-compatible).

---

## 🧑‍💻 Author

**@0x7b**  
- Telegram: [t.me/db0x169](https://t.me/the0x7b)  
- GitHub: [github.com/x0x7b](https://github.com/x0x7b)

---

## 📄 License

MIT © 0x7b — Free for personal and commercial use.
