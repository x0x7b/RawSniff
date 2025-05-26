# RawSniff
![image](https://github.com/user-attachments/assets/9a086f9a-926d-40ef-8b6a-932fab55ae28)


RawSniff - simple network sniffer, written on Golang with gopacket and tview


## Features

- Select network interface to capture traffic from
- Apply and dynamically change BPF (Berkeley Packet Filter) filters
- Capture and display detailed information for TCP and UDP packets
  - TCP flags (SYN, ACK, FIN, RST)
  - Sequence and acknowledgment numbers
  - Window size, checksum, urgent pointer
- Scrollable, color-coded terminal UI built with tview
- Real-time status updates on filter application and errors
- Simple, minimalistic design focused on raw packet data monitoring
- Graceful shutdown and resource cleanup


# Installation:
  1. Clone repository
```bash
   git clone https://github.com/x0x7b/RawSniff.git
   cd RawSniff
```
2. Download dependencies:
```bash
go mod tidy
```
3. Run the app
```bash
go run main.go
```


