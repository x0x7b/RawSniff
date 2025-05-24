package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rivo/tview"
)

var packetsView *tview.TextView
var ifcname string

const (
	ProtoTCP  = 1 << 0
	ProtoUDP  = 1 << 1
	ProtoICMP = 1 << 2
	Port80    = 1 << 3
	Port443   = 1 << 4
	Local     = 1 << 5
	Inbound   = 1 << 6
	Outbound  = 1 << 7
)

func Capture(handle *pcap.Handle, app *tview.Application, packetsView *tview.TextView, filterChan chan string, statusView *tview.TextView) {
	go func() {
		for newFilter := range filterChan {
			err := handle.SetBPFFilter(newFilter)
			if err != nil {
				app.QueueUpdateDraw(func() {
					statusView.Write([]byte(fmt.Sprintf("[red]Error setting filter: %v\n", err)))
				})
			} else {
				app.QueueUpdateDraw(func() {
					statusView.Write([]byte(fmt.Sprintf("[green]Filter applied: %v\n", newFilter)))
					packetsView.SetText("")
				})
			}
		}

	}()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			switch ip.Protocol {
			case layers.IPProtocolTCP:
				tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
				info := fmt.Sprintf(
					"[yellow]%-6s [green]%s:%d -> %s:%d\n[purple]TCP Flags: SYN=%t ACK=%t FIN=%t RST=%t\nSeq: %d Ack: %d Window: %d\nCheckSum: %d Urgent: %d\n[white]%s\n",
					ip.Protocol, ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort,
					tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST,
					tcp.Seq, tcp.Ack, tcp.Window,
					tcp.Checksum, tcp.Urgent,
					strings.Repeat("-", 80),
				)

				app.QueueUpdateDraw(func() {
					packetsView.Write([]byte(info))
					packetsView.ScrollToEnd()
				})

			case layers.IPProtocolUDP:
				udp, _ := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
				info := fmt.Sprintf(
					"[yellow]%-6s [green]%s:%d -> %s:%d\n[purple]Length: %d\nChecksum: %d\n[white]%s\n",
					ip.Protocol, ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort,
					udp.Length, udp.Checksum,
					strings.Repeat("-", 80),
				)
				app.QueueUpdateDraw(func() {
					packetsView.Write([]byte(info))
					packetsView.ScrollToEnd()
				})

			}
		}
	}
}

func selectInterface(app *tview.Application) *pcap.Handle {
	ifc, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	selected := make(chan int)
	list := tview.NewList()
	for i, iface := range ifc {
		desc := iface.Description
		list.AddItem(iface.Name, desc, rune('1'+i), func(index int) func() {
			return func() {
				selected <- index
			}

		}(i))
	}

	list.SetBorder(true).SetTitle("RawSniff > Select network interface")

	go func() {
		if err := app.SetRoot(list, true).Run(); err != nil {
			log.Fatal(err)
		}
	}()

	selectedIndex := <-selected

	app.Stop()
	ifcname = ifc[selectedIndex].Name
	handle, err := pcap.OpenLive(ifc[selectedIndex].Name, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	return handle
}

func main() {
	filterChan := make(chan string, 10)
	app := tview.NewApplication()
	packetsView = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetChangedFunc(func() {
			app.Draw()
		})

	filterForm := tview.NewForm()
	filterForm.
		AddInputField("Filter", "", 30, nil, nil).
		AddButton("Apply", func() {
			filter := filterForm.GetFormItemByLabel("Filter").(*tview.InputField).GetText()
			go func() {
				filterChan <- filter
			}()

			filterInput := filterForm.GetFormItemByLabel("Filter").(*tview.InputField)
			filterInput.SetText("")
			app.SetFocus(filterInput)

		}).
		AddButton("Quit", func() {
			app.Stop()
		}).
		SetButtonsAlign(tview.AlignCenter).
		SetBorder(true).
		SetTitle("Filter")
	statusView := tview.NewTextView()
	statusView.SetDynamicColors(true)
	statusView.SetScrollable(true)
	statusView.SetTextAlign(tview.AlignLeft)
	statusView.SetBorder(true)
	statusView.SetTitle("Status")

	devView := tview.NewTextView()
	devView.SetDynamicColors(true)
	devView.SetTextAlign(tview.AlignCenter)
	devView.SetBorder(true)
	aboutText := `[white]RawSniff v1.0

[gray]Author: [yellow]0x7b
[gray]Purpose: [white]Capture network packets and show info.

[gray]Use filters to limit captured data.
This is a [red]simple[white] tool for monitoring network traffic.

No gimmicks, no extras.
Just raw packet data.

[gray]Links:
[blue]GitHub: [white]https://github.com/x0x7b
[blue]Telegram: [white]https://t.me/db0x169

fuck you.`
	devView.SetText(aboutText)

	rightPane := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(filterForm, 7, 1, true).
		AddItem(statusView, 0, 1, false).
		AddItem(devView, 0, 1, false)

	layout := tview.NewFlex().
		AddItem(packetsView, 0, 3, false).
		AddItem(rightPane, 40, 1, true)

	app.SetRoot(layout, true)

	app.SetFocus(filterForm.GetFormItemByLabel("Filter"))
	handle := selectInterface(app)
	defer handle.Close()
	title := fmt.Sprintf("RawSniff > %s", ifcname)
	packetsView.SetBorder(true).SetTitle(title).SetTitleColor(tcell.ColorPurple)
	go Capture(handle, app, packetsView, filterChan, statusView)

	go func() {
		for {
			app.QueueUpdateDraw(func() {
				packetsView.Write([]byte("Waiting for packets...\n"))
			})
			time.Sleep(5 * time.Second)
		}
	}()

	if err := app.SetRoot(layout, true).SetFocus(filterForm).Run(); err != nil {
		log.Fatal(err)
	}
}
