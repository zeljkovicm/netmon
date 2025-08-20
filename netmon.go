package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const CSV = "csm2networkreport.csv"

var (
	snapshot_len int32         = 1024
	promiscuous  bool          = false
	timeout      time.Duration = 30 * time.Second
)
var trackedIPs = make(map[string]struct{})

// Mutex is protecting CSV file from concurently writting to it
var fileMutex sync.Mutex
var csvWriter *csv.Writer
var csvFile *os.File

func writeToCSVRow(timestamp time.Time, ip, direction string, size uint64) {
	fileMutex.Lock()
	defer fileMutex.Unlock()
	record := []string{
		timestamp.Format(time.RFC3339),
		ip,
		direction,
		strconv.FormatUint(size, 10),
	}
	if err := csvWriter.Write(record); err != nil {
		log.Println("Error writting row:", err)
	}
	csvWriter.Flush() // Flush data to disk
}
func processPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)
	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()
	packetSize := uint64(len(packet.Data()))
	// Checking if our entered IP addresses are matching with found ones
	if _, ok := trackedIPs[srcIP]; ok {
		writeToCSVRow(time.Now(), srcIP, "Download", packetSize)
		fmt.Printf("Inbound traffic (Download) from '%s' (size: %d bytes)\n", srcIP, packetSize)
		return
	}
	if _, ok := trackedIPs[dstIP]; ok {
		writeToCSVRow(time.Now(), dstIP, "Upload", packetSize)
		fmt.Printf("Outbound traffic (Upload) to '%s' (size: %d bytes)\n", dstIP, packetSize)
		return
	}
}
func main() {
	fmt.Println("Enter IP addresses you would like to monitor (comma delimited):")
	reader := bufio.NewReader(os.Stdin)
	inputIPs, _ := reader.ReadString('\n')
	inputIPs = strings.TrimSpace(inputIPs)
	ipList := strings.Split(inputIPs, ",")
	for _, ipStr := range ipList {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr != "" && net.ParseIP(ipStr) != nil {
			trackedIPs[ipStr] = struct{}{}
		}
	}
	if len(trackedIPs) == 0 {
		log.Fatal("You haven't entered any valid IP address.")
	}
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("Error finding network adapter:", err)
	}
	fmt.Println("\nAvailable network adapters:")
	for i, dev := range devices {
		fmt.Printf("%d: %s\n", i, dev.Description)
		if dev.Description == "" {
			fmt.Printf("   (Name: %s)\n", dev.Name)
		}
	}
	fmt.Println()
	fmt.Print("Enter adapter number you would like to monitor: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	choice, err := strconv.Atoi(input)
	if err != nil || choice < 0 || choice >= len(devices) {
		log.Fatal("Please enter valid number.")
	}
	selectedDevice := devices[choice]
	fmt.Printf("Monitoring adapter: %s\n", selectedDevice.Description)
	fmt.Printf("Monitoring IPs: %v\n", ipList)
	fmt.Printf("Please wait... Press Ctrl+C to stop the program.\n\n")
	if err := initCSVFile(); err != nil {
		log.Fatal(err)
	}
	defer func() {
		csvWriter.Flush()
		csvFile.Close()
		log.Println("Writting to CSV completed.")
	}()
	handle, err := pcap.OpenLive(selectedDevice.Name, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatalf("Error accessing adapter %s: %v", selectedDevice.Name, err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}
func initCSVFile() error {
	var err error
	csvFile, err = os.Create(CSV)
	if err != nil {
		return fmt.Errorf("Error creating CSV: %w", err)
	}
	csvWriter = csv.NewWriter(csvFile)
	headers := []string{"Timestamp", "IP", "Traffic", "Bytes"}
	if err := csvWriter.Write(headers); err != nil {
		return fmt.Errorf("Error writting header to CSV: %w", err)
	}
	csvWriter.Flush()
	return nil
}
