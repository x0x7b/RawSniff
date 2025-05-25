package main

import (
	"encoding/hex"
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
var helpText string
var payloads bool
var paused bool

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
	if !paused {
		for packet := range packetSource.Packets() {
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				switch ip.Protocol {
				case layers.IPProtocolTCP:
					tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
					info := fmt.Sprintf(
						"[lime]%-6s [green]%s:%d -> %s:%d\n[purple]TCP Flags: SYN=%t ACK=%t FIN=%t RST=%t\nSeq: %d Ack: %d Window: %d\nCheckSum: %d Urgent: %d\n[gray]%s\n",
						ip.Protocol, ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort,
						tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST,
						tcp.Seq, tcp.Ack, tcp.Window,
						tcp.Checksum, tcp.Urgent,
						strings.Repeat("─", 88),
					)
					if appLayer := packet.ApplicationLayer(); appLayer != nil && payloads {
						payload := appLayer.Payload()
						if len(payload) > 0 {
							info += fmt.Sprintf("[blue]Payload:\n%s\n", hex.Dump(payload))
						}
					}
					app.QueueUpdateDraw(func() {
						packetsView.Write([]byte(info))
						packetsView.ScrollToEnd()
					})

				case layers.IPProtocolUDP:
					udp, _ := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
					info := fmt.Sprintf(
						"[yellow]%-6s [green]%s:%d -> %s:%d\n[purple]Length: %d\nChecksum: %d\n[gray]%s\n",
						ip.Protocol, ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort,
						udp.Length, udp.Checksum,
						strings.Repeat("─", 88),
					)
					app.QueueUpdateDraw(func() {
						packetsView.Write([]byte(info))
						packetsView.ScrollToEnd()
					})
				case layers.IPProtocolICMPv4:
					icmp, _ := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
					info := fmt.Sprintf(
						"[red]%-6s [green]%s -> %s\nICMPv4 Type: %d Code: %d\nID: %d Seq: %d\nChecksum: %d\n[gray]%s",
						ip.Protocol, ip.SrcIP, ip.DstIP,
						icmp.TypeCode.Type(), icmp.TypeCode.Code(),
						icmp.Id, icmp.Seq,
						icmp.Checksum,
						strings.Repeat("─", 88),
					)
					app.QueueUpdateDraw(func() {
						packetsView.Write([]byte(info))
						packetsView.ScrollToEnd()
					})

				}
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
	tview.Styles.PrimitiveBackgroundColor = tcell.ColorBlack
	tview.Styles.ContrastBackgroundColor = tcell.ColorDarkGray
	tview.Styles.MoreContrastBackgroundColor = tcell.ColorGray
	tview.Styles.PrimaryTextColor = tcell.ColorWhite
	tview.Styles.BorderColor = tcell.ColorGray
	tview.Styles.TitleColor = tcell.ColorGray

	helpText = `Aviable commands:
		-show-payloads
		-hide-payloads(default)
		also u can use BPF filters`
	filterChan := make(chan string, 10)
	app := tview.NewApplication()
	packetsView = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetChangedFunc(func() {
			app.Draw()
		})

	filterForm := tview.NewForm()
	filterForm.SetButtonBackgroundColor(tcell.ColorGray)
	filterForm.SetButtonTextColor(tcell.ColorWhite)
	filterForm.
		SetButtonActivatedStyle(tcell.StyleDefault.
			Background(tcell.ColorLightGray).
			Foreground(tcell.ColorWhite))
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
		SetTitle("Console")
	filterForm.SetFieldBackgroundColor(tcell.ColorWhite)
	filterForm.SetFieldTextColor(tcell.ColorBlack)
	filterForm.SetLabelColor(tcell.ColorWhite)

	statusView := tview.NewTextView()
	statusView.SetDynamicColors(true)
	statusView.SetScrollable(true)
	statusView.SetTextAlign(tview.AlignLeft)
	statusView.SetBorder(true)
	statusView.SetTitle("Output")

	devView := tview.NewTextView()
	devView.SetDynamicColors(true)
	devView.SetTextAlign(tview.AlignCenter)
	devView.SetBorder(true)
	aboutText := `[white]RawSniff v1.1

[gray]Author: [yellow]0x7b

[gray]Links:
[blue]GitHub: [white]https://github.com/x0x7b
[blue]Telegram: [white]https://t.me/db0x169

[red::]fuck you.`
	devView.SetText(aboutText)
	var payloadButton *tview.Button

	payloadButton = tview.NewButton("Show Payloads").
		SetSelectedFunc(func() {
			payloads = !payloads
			statusView.Write([]byte(fmt.Sprintf("Show payloads: %v\n", payloads)))
			if payloads {
				payloadButton.SetLabel("Hide Payloads")
			} else {
				payloadButton.SetLabel("Show Payloads")
			}
			statusView.ScrollToEnd()
		})

	payloadButton.
		SetActivatedStyle(tcell.StyleDefault.
			Background(tcell.ColorLightGray).
			Foreground(tcell.ColorWhite))

	payloadButton.SetBackgroundColor(tcell.ColorGray)
	payloadButton.SetBorder(true)
	payloadButton.SetBorderColor(tcell.ColorBlack)

	payloadButton.SetStyle(tcell.StyleDefault.
		Background(tcell.ColorGray).
		Foreground(tcell.ColorWhite))

	var pauseButton *tview.Button

	pauseButton = tview.NewButton("Pause").
		SetSelectedFunc(func() {
			paused = !paused
			if paused {
				statusView.Write([]byte("Output paused\n"))
			} else {
				statusView.Write([]byte("Output resumed\n"))
			}
		})

	pauseButton.
		SetActivatedStyle(tcell.StyleDefault.
			Background(tcell.ColorLightGray).
			Foreground(tcell.ColorWhite))

	pauseButton.SetBackgroundColor(tcell.ColorGray)
	pauseButton.SetBorder(true)
	pauseButton.SetBorderColor(tcell.ColorBlack)

	pauseButton.SetStyle(tcell.StyleDefault.
		Background(tcell.ColorGray).
		Foreground(tcell.ColorWhite))

	commandsView := tview.NewFlex()
	commandsView.SetDirection(tview.FlexRow)
	commandsView.AddItem(payloadButton, 3, 1, true)
	commandsView.AddItem(pauseButton, 3, 1, true)
	commandsView.SetBorder(true)
	commandsView.SetTitle("Commands")

	rightPane := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(commandsView, 0, 1, false).
		AddItem(devView, 0, 1, false)

	bottomLeft := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(filterForm, 0, 1, true).
		AddItem(statusView, 0, 1, false)

	leftPane := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(packetsView, 0, 3, false).
		AddItem(bottomLeft, 0, 1, true)

	layout := tview.NewFlex().
		AddItem(leftPane, 0, 3, false).
		AddItem(rightPane, 0, 1, true)

	app.SetRoot(layout, true)

	app.SetFocus(filterForm.GetFormItemByLabel("Filter"))
	focusables := []tview.Primitive{
		filterForm,
		payloadButton,
		pauseButton,
		packetsView,
	}
	currentFocus := 0
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.Key(tcell.KeyBacktab) {
			currentFocus = (currentFocus + 1) % len(focusables)
			app.SetFocus(focusables[currentFocus])
			return nil
		}
		return event

	})
	handle := selectInterface(app)
	defer handle.Close()
	title := fmt.Sprintf("RawSniff > %s", ifcname)
	packetsView.SetBorder(true).SetTitle(title).SetTitleColor(tcell.ColorGray)
	packetsView.SetScrollable(true)
	go Capture(handle, app, packetsView, filterChan, statusView)

	go func() {
		for {
			app.QueueUpdateDraw(func() {
				packetsView.Write([]byte("[white]Waiting for packets...\n"))
			})
			time.Sleep(5 * time.Second)
		}
	}()

	if err := app.SetRoot(layout, true).SetFocus(filterForm).Run(); err != nil {
		log.Fatal(err)
	}
}
