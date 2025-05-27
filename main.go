package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/rivo/tview"
)

var packetsView *tview.TextView
var filterForm *tview.Form
var ifcname string
var payloads bool
var paused bool
var maxlines int = 500
var writer *pcapgo.Writer
var write bool
var filename string = "packets.pcap"
var statistic *tview.TextView
var tcp, udp, icmp int = 0, 0, 0

func Capture(handle *pcap.Handle, app *tview.Application, packetsView *tview.TextView, filterChan chan string, statusView *tview.TextView) {
	go func() {
		for newFilter := range filterChan {
			if len(newFilter) >= 13 && newFilter[:13] == "-set-filename" {
				filename = newFilter[14:]
				h, m, s := time.Now().Clock()
				statusView.Write([]byte(fmt.Sprintf("%v:%v:%v [green] INFO [white] ↓\nNew filename set: %s\n", h, m, s, filename)))
				continue
			}
			err := handle.SetBPFFilter(newFilter)
			if err != nil {
				app.QueueUpdateDraw(func() {
					h, m, s := time.Now().Clock()
					statusView.Write([]byte(fmt.Sprintf("[%v:%v:%v] [red] ERROR [white]↓\nError setting filter: %v\n", h, m, s, err)))
					statusView.ScrollToEnd()

				})
			} else {
				app.QueueUpdateDraw(func() {
					h, m, s := time.Now().Clock()
					statusView.Write([]byte(fmt.Sprintf("%v:%v:%v [green] INFO [white] ↓\nFilter applied: %v\n", h, m, s, newFilter)))
					packetsView.SetText("")
					statusView.ScrollToEnd()
				})
			}
		}
	}()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		if !paused {
			if write {
				writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
				h, m, s := time.Now().Clock()
				writeLog(app, statusView, fmt.Sprintf("%v:%v:%v [green] INFO [white] ↓\nPacket saved to file\n", h, m, s))
			}
			lines := strings.Split(packetsView.GetText(true), "\n")
			if len(lines) > maxlines {
				packetsView.SetText("")
				h, m, s := time.Now().Clock()
				statusView.Write([]byte(fmt.Sprintf("%v:%v:%v [green] INFO [white] ↓\nCleaned packets list\n", h, m, s)))
				statusView.ScrollToEnd()

			}
			_, _, width, _ := packetsView.GetRect()
			_, _, width1, _ := filterForm.GetRect()
			filterForm.GetFormItemByLabel("Filter").(*tview.InputField).SetFieldWidth(width1 / 2)
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				switch ip.Protocol {
				case layers.IPProtocolTCP:
					tcp++
					tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
					info := fmt.Sprintf(
						"\n[lime]%-6s [green]%s:%d -> %s:%d\n[purple]TCP Flags: SYN=%t ACK=%t FIN=%t RST=%t\nSeq: %d Ack: %d Window: %d\nCheckSum: %d Urgent: %d\n[gray]%s",
						ip.Protocol, ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort,
						tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST,
						tcp.Seq, tcp.Ack, tcp.Window,
						tcp.Checksum, tcp.Urgent,
						strings.Repeat("─", width-2),
					)

					if appLayer := packet.ApplicationLayer(); appLayer != nil && payloads {
						payload := appLayer.Payload()
						if len(payload) > 0 {
							info += fmt.Sprintf("[blue]Payload:\n%s", hex.Dump(payload))
						}
					}
					writeLog(app, packetsView, info)

				case layers.IPProtocolUDP:
					udp++
					udp, _ := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
					info := fmt.Sprintf(
						"\n[yellow]%-6s [green]%s:%d -> %s:%d\n[purple]Length: %d\nChecksum: %d\n[gray]%s",
						ip.Protocol, ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort,
						udp.Length, udp.Checksum,
						strings.Repeat("─", width-2),
					)
					writeLog(app, packetsView, info)

				case layers.IPProtocolICMPv4:
					icmp++
					icmp, _ := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
					info := fmt.Sprintf(
						"\n[red]%-6s [green]%s -> %s\nICMPv4 Type: %d Code: %d\nID: %d Seq: %d\nChecksum: %d\n[gray]%s",
						ip.Protocol, ip.SrcIP, ip.DstIP,
						icmp.TypeCode.Type(), icmp.TypeCode.Code(),
						icmp.Id, icmp.Seq,
						icmp.Checksum,
						strings.Repeat("─", width-2),
					)
					writeLog(app, packetsView, info)
				}
				updateStatistic()
			}
		}
	}
}

func selectInterface(app *tview.Application) *pcap.Handle {
	ifc, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	if len(ifc) == 0 {
		log.Fatal("there is no network interfaces")
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

func StyleButton(button *tview.Button) {
	button.
		SetActivatedStyle(tcell.StyleDefault.
			Background(tcell.ColorLightGray).
			Foreground(tcell.ColorWhite))

	button.SetBackgroundColor(tcell.ColorGray)
	button.SetBorder(true)
	button.SetBorderColor(tcell.ColorBlack)

	button.SetStyle(tcell.StyleDefault.
		Background(tcell.ColorGray).
		Foreground(tcell.ColorWhite))
}

func writeLog(app *tview.Application, TextView *tview.TextView, msg string) {
	app.QueueUpdateDraw(func() {
		TextView.Write([]byte(msg))
		TextView.ScrollToEnd()
	})

}

func savePacketsToFile() *pcapgo.Writer {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	pcapgoWriter := pcapgo.NewWriter(file)
	if err := pcapgoWriter.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		log.Fatal(err)
	}
	return pcapgoWriter
}

func updateStatistic() {
	statistic.SetText(fmt.Sprintf(
		"[lime]TCP: %d [yellow]UDP: %d [red]ICMP: %d",
		tcp, udp, icmp,
	))
}

func main() {
	tview.Styles.PrimitiveBackgroundColor = tcell.ColorBlack
	tview.Styles.ContrastBackgroundColor = tcell.ColorDarkGray
	tview.Styles.MoreContrastBackgroundColor = tcell.ColorGray
	tview.Styles.PrimaryTextColor = tcell.ColorWhite
	tview.Styles.BorderColor = tcell.ColorGray
	tview.Styles.TitleColor = tcell.ColorGray

	filterChan := make(chan string, 10)
	app := tview.NewApplication()
	packetsView = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetChangedFunc(func() {
			app.Draw()
		})

	filterForm = tview.NewForm()
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
		SetButtonsAlign(tview.AlignCenter).
		SetBorder(true).
		SetTitle("Console")
	filterForm.SetFieldBackgroundColor(tcell.ColorWhite)
	filterForm.SetFieldTextColor(tcell.ColorBlack)
	filterForm.SetLabelColor(tcell.ColorWhite)
	_, _, width, _ := filterForm.GetRect()
	filterForm.GetFormItemByLabel("Filter").(*tview.InputField).SetFieldWidth(width / 2)

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
	aboutText := `[white]RawSniff v1.10
[gray]Author: [yellow]0x7b

[gray]Links:
[white]https://github.com/x0x7b
[white]https://t.me/db0x169

[red::]fuck you.`
	devView.SetText(aboutText)
	var payloadButton *tview.Button

	payloadButton = tview.NewButton("Show Payloads").
		SetSelectedFunc(func() {
			payloads = !payloads
			h, m, s := time.Now().Clock()
			statusView.Write([]byte(fmt.Sprintf("%v:%v:%v [green] INFO [white] ↓\nShow payloads: %v\n", h, m, s, payloads)))
			if payloads {
				payloadButton.SetLabel("Hide Payloads")
			} else {
				payloadButton.SetLabel("Show Payloads")
			}
			statusView.ScrollToEnd()
		})

	StyleButton(payloadButton)

	var pauseButton *tview.Button

	pauseButton = tview.NewButton("Pause").
		SetSelectedFunc(func() {
			paused = !paused
			if paused {
				h, m, s := time.Now().Clock()
				statusView.Write([]byte(fmt.Sprintf("%v:%v:%v [green] INFO [white] ↓\nOutput paused\n", h, m, s)))
				packetsView.Write([]byte("Output paused\n"))
				pauseButton.SetLabel("Resume")
			} else {
				pauseButton.SetLabel("Pause")
				packetsView.Write([]byte("Output resumed\n"))
				h, m, s := time.Now().Clock()
				statusView.Write([]byte(fmt.Sprintf("%v:%v:%v [green] INFO [white] ↓\nOutput resumed\n", h, m, s)))
			}
		})

	StyleButton(pauseButton)

	quitButton := tview.NewButton("Quit").
		SetSelectedFunc(func() {
			app.Stop()
		})
	StyleButton(quitButton)

	saveButton := tview.NewButton("Save packets").
		SetSelectedFunc(func() {
			write = !write
			writer = savePacketsToFile()
			h, m, s := time.Now().Clock()
			statusView.Write([]byte(fmt.Sprintf("%v:%v:%v [green] INFO [white] ↓\nStarting saving packets in file %s(tip: you can set you own filename by -seti-flename filename.pcap) \n", h, m, s, filename)))
		})

	StyleButton(saveButton)

	statistic = tview.NewTextView()
	statistic.SetDynamicColors(true)
	statistic.SetTextAlign(tview.AlignCenter)
	statistic.SetBorder(true)
	statistic.SetTitle("Statistics")

	commandsView := tview.NewFlex()
	commandsView.SetDirection(tview.FlexRow)
	commandsView.AddItem(payloadButton, 3, 1, true)
	commandsView.AddItem(pauseButton, 3, 1, true)
	commandsView.AddItem(saveButton, 3, 1, true)
	commandsView.AddItem(quitButton, 3, 1, true)
	commandsView.AddItem(statistic, 3, 0, false)

	commandsView.SetBorder(true)
	commandsView.SetTitle("Commands")

	rightPane := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(commandsView, 0, 1, false).
		AddItem(devView, 10, 0, false)

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
		saveButton,
		quitButton,
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
			if !paused {
				app.QueueUpdateDraw(func() {
					packetsView.Write([]byte("\n[white]Waiting for packets...\n"))
				})
				time.Sleep(5 * time.Second)
			} else {
				continue
			}

		}
	}()

	if err := app.SetRoot(layout, true).SetFocus(filterForm).Run(); err != nil {
		log.Fatal(err)
	}
}
