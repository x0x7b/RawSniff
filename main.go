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

var packetsView *tview.List
var filterForm *tview.Form
var ifcname string
var payloads bool = true
var paused bool
var maxlines int = 1000
var writer *pcapgo.Writer
var write bool
var filename string = "packets.pcap"
var statistic *tview.TextView
var tcpCounter, udpCounter, icmpCounter int = 0, 0, 0
var info []string
var packets [][]string
var packetsperSecond int = 0
var ipList = make(map[string]int)
var rating *tview.TextView

func Capture(handle *pcap.Handle, app *tview.Application, packetsView *tview.List, filterChan chan string, statusView *tview.TextView) {
	go func() {
		for newFilter := range filterChan {
			if len(newFilter) >= 14 && newFilter[:13] == "-set-filename" {
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
					packetsView.Clear()
					packets = packets[:0]
					statusView.ScrollToEnd()
				})
			}
		}
	}()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {

		info = make([]string, 3)
		if !paused {
			if write {
				writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
				h, m, s := time.Now().Clock()
				writeLog(app, statusView, fmt.Sprintf("%v:%v:%v [green] INFO [white] ↓\nPacket saved to file\n", h, m, s))
			}
			if packetsView.GetItemCount() > maxlines {
				packetsView.Clear()
				packets = packets[:0]
				h, m, s := time.Now().Clock()
				statusView.Write([]byte(fmt.Sprintf("%v:%v:%v [green] INFO [white] ↓\nCleaned packets list\n", h, m, s)))
				statusView.ScrollToEnd()

			}
			_, _, width, _ := filterForm.GetRect()
			filterForm.GetFormItemByLabel("Filter").(*tview.InputField).SetFieldWidth(width / 2)
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				if ipList[ip.SrcIP.String()] == 0 {
					ipList[ip.SrcIP.String()] = 1
				} else {
					ipList[ip.SrcIP.String()] += 1
				}
				go updateRating(app)
				switch ip.Protocol {
				case layers.IPProtocolTCP:
					tcpCounter++
					tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
					info[0] = fmt.Sprintf("%v[lime]%-6s [green]%s:%d -> %s:%d", packet.Metadata().Timestamp.Format("15:04:05 "), ip.Protocol, ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
					info[1] = formatDetailTCP(tcp)

					if appLayer := packet.ApplicationLayer(); appLayer != nil && payloads {
						payload := appLayer.Payload()
						if strings.HasPrefix(string(payload), "GET") ||
							strings.HasPrefix(string(payload), "POST") ||
							strings.HasPrefix(string(payload), "HEAD") ||
							strings.HasPrefix(string(payload), "PUT") ||
							strings.HasPrefix(string(payload), "DELETE") ||
							strings.HasPrefix(string(payload), "OPTIONS") ||
							strings.HasPrefix(string(payload), "HTTP/1.1") ||
							strings.HasPrefix(string(payload), "HTTP/1.0") {
							info[0] += fmt.Sprintf("%17s", "[purple]HTTP")
						}
						if len(payload) > 0 {
							info[2] = fmt.Sprintf("[blue]Payload:\n\n%s", hex.Dump(payload))
						}
					}

				case layers.IPProtocolUDP:
					udpCounter++
					udp, _ := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
					info[0] = fmt.Sprintf("%v [yellow]%-6s [green]%s:%d -> %s:%d", packet.Metadata().Timestamp.Format("15:04:05 "), ip.Protocol, ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort)
					info[1] = fmt.Sprintf(
						"[blue]Length: %d\nChecksum: %d\n[gray]",
						udp.Length, udp.Checksum,
					)

				case layers.IPProtocolICMPv4:
					icmpCounter++
					icmp, _ := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
					info = make([]string, 3)
					info[0] = fmt.Sprintf("%v[red]%-6s [green]%s -> %s", packet.Metadata().Timestamp.Format("15:04:05 "), ip.Protocol, ip.SrcIP, ip.DstIP)

					info[1] = fmt.Sprintf(
						"\nICMPv4 Type: %d Code: %d\nID: %d Seq: %d\nChecksum: %d\n[gray]",
						icmp.TypeCode.Type(), icmp.TypeCode.Code(),
						icmp.Id, icmp.Seq,
						icmp.Checksum,
					)
					info[2] = ""

				}
				addPacketToList(app, packetsView, info)
			}
			updateStatistic(app)
			packetsView.SetCurrentItem(packetsView.GetItemCount() - 1)
			packetsperSecond++
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

func updateStatistic(app *tview.Application) {
	app.QueueUpdateDraw(func() {
		statistic.SetText(fmt.Sprintf(
			"total packages: %d\n %d last secound\n[lime]TCP: %d\n[yellow]UDP: %d\n[red]ICMP: %d",
			tcpCounter+udpCounter+icmpCounter, packetsperSecond, tcpCounter, udpCounter, icmpCounter,
		))
	})

}

func addPacketToList(app *tview.Application, packetsView *tview.List, info []string) {
	packets = append(packets, info)
	index := len(packets) - 1
	_, _, width, _ := packetsView.GetInnerRect()
	divider := "[gray]"
	divider += strings.Repeat("─", width)
	app.QueueUpdateDraw(func() {
		if len(info) >= 2 {
			packetsView.AddItem(fmt.Sprintf("[%d] %s", index, info[0]), divider, 0, nil)
		} else if len(info) == 1 {
			packetsView.AddItem(info[0], divider, 0, nil)
		} else {
			packetsView.AddItem("Unknown packet", "", 0, nil)
		}
		packetsView.SetCurrentItem(packetsView.GetItemCount() - 1)
	})

}

func formatDetailTCP(tcp *layers.TCP) string {
	flags := []string{}
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	details := fmt.Sprintf(
		"[purple]%s[white]\n[purple]Seq=[white]%d  [purple]Ack=[white]%d\n[purple]Window=[white]%d  [purple]CheckSum=[white]%d  [purple]Urgent=[white]%d",
		strings.Join(flags, " "),
		tcp.Seq, tcp.Ack, tcp.Window, tcp.Checksum, tcp.Urgent,
	)

	return details
}

func formatDetail(detail []string) string {
	if detail[2] == "" {
		return fmt.Sprintf("%v\n%v\nthere is no payload", detail[0], detail[1])
	}
	return fmt.Sprintf("%v\n%v\n[blue]%v", detail[0], detail[1], detail[2])
}

func updateRating(app *tview.Application) {
	var blya strings.Builder
	for k, v := range ipList {
		blya.WriteString(fmt.Sprintf("%v:%v\n", k, v))
	}
	app.QueueUpdateDraw(func() {
		rating.SetText(blya.String())
	})
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

	packetsView = tview.NewList()

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
[white]github.com/x0x7b
[white]t.me/db0x169

[red::]fuck you.`
	devView.SetText(aboutText)

	var pauseButton *tview.Button

	pauseButton = tview.NewButton("Pause").
		SetSelectedFunc(func() {
			paused = !paused
			if paused {
				h, m, s := time.Now().Clock()
				statusView.Write([]byte(fmt.Sprintf("%v:%v:%v [green] INFO [white] ↓\nOutput paused\n", h, m, s)))
				pauseButton.SetLabel("Resume")
			} else {
				pauseButton.SetLabel("Pause")
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

	rating = tview.NewTextView()
	rating.SetDynamicColors(true)
	rating.SetBorder(true)
	rating.SetTitle("Rating")

	commandsView := tview.NewFlex()
	commandsView.SetDirection(tview.FlexRow)
	commandsView.AddItem(pauseButton, 3, 1, true)
	commandsView.AddItem(saveButton, 3, 1, true)
	commandsView.AddItem(quitButton, 3, 1, true)
	commandsView.AddItem(statistic, 10, 0, false)
	commandsView.AddItem(rating, 10, 1, false)

	commandsView.SetBorder(true)
	commandsView.SetTitle("Commands")

	detailView := tview.NewTextView()
	detailView.SetDynamicColors(true)
	detailView.SetBorder(true)
	detailView.SetTitle("Details")

	mainPanel := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(packetsView, 0, 1, true).
		AddItem(detailView, 0, 1, false)

	rightPane := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(commandsView, 0, 1, false).
		AddItem(devView, 10, 0, false)

	bottomLeft := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(filterForm, 0, 1, true).
		AddItem(statusView, 0, 1, false)

	leftPane := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(mainPanel, 0, 3, false).
		AddItem(bottomLeft, 0, 1, true)

	layout := tview.NewFlex().
		AddItem(leftPane, 0, 5, false).
		AddItem(rightPane, 0, 1, true)

	app.SetRoot(layout, true)
	app.EnableMouse(true)

	app.SetFocus(filterForm.GetFormItemByLabel("Filter"))
	focusables := []tview.Primitive{
		filterForm,
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
		} else if event.Key() == tcell.Key(tcell.KeyCtrlC) {
			app.Stop()
			print("Ctrl+C pressed, exiting...\n")
			os.Exit(0)
		} else if event.Key() == tcell.Key(tcell.KeyCtrlP) {
			app.SetFocus(packetsView)
		} else if event.Key() == tcell.Key(tcell.KeyCtrlD) {
			paused = !paused
			if paused {
				h, m, s := time.Now().Clock()
				statusView.Write([]byte(fmt.Sprintf("%v:%v:%v [green] INFO [white] ↓\nOutput paused\n", h, m, s)))
				pauseButton.SetLabel("Resume")
			} else {
				pauseButton.SetLabel("Pause")
				h, m, s := time.Now().Clock()
				statusView.Write([]byte(fmt.Sprintf("%v:%v:%v [green] INFO [white] ↓\nOutput resumed\n", h, m, s)))
			}
		}
		return event

	})
	handle := selectInterface(app)
	defer handle.Close()
	title := fmt.Sprintf("RawSniff > %s", ifcname)
	packetsView.SetBorder(true).SetTitle(title).SetTitleColor(tcell.ColorGray)
	packetsView.SetSelectedStyle(
		tcell.StyleDefault.
			Background(tcell.NewHexColor(0x2e2e2e)).
			Foreground(tcell.ColorDefault),
	)
	packetsView.SetChangedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		detailView.SetText(formatDetail(packets[index]))
	})
	go Capture(handle, app, packetsView, filterChan, statusView)
	go func() {
		for {
			time.Sleep(time.Second)
			packetsperSecond = 0
			updateStatistic(app)

		}
	}()

	if err := app.SetRoot(layout, true).SetFocus(filterForm).Run(); err != nil {
		log.Fatal(err)
	}
}
