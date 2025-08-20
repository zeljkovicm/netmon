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
	snapshotLenght int32         = 1024
	promiscuous    bool          = false
	timeout        time.Duration = 30 * time.Second
)

var trackedIPs = make(map[string]struct{})

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
		log.Println("Error writing row:", err)
	}
	// Flush data to disk immediately to ensure logs are up-to-date.
	csvWriter.Flush()
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

	fmt.Println("Enter IP addresses or FQDNs to monitor (comma-separated):")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal("Error reading input:", err)
	}

	rawInputList := strings.Split(strings.TrimSpace(input), ",")
	var resolvedIPs []string

	for _, entry := range rawInputList {
		trimmedEntry := strings.TrimSpace(entry)
		if trimmedEntry == "" {
			continue
		}

		// Check if the entry is a valid IP address.
		if net.ParseIP(trimmedEntry) != nil {
			trackedIPs[trimmedEntry] = struct{}{}
			resolvedIPs = append(resolvedIPs, trimmedEntry)
			continue
		}

		// If not an IP, try to resolve it as an FQDN.
		fmt.Printf("Attempting to resolve FQDN: %s\n", trimmedEntry)
		ips, resolveErr := net.LookupIP(trimmedEntry)
		if resolveErr != nil {
			fmt.Printf("Could not resolve FQDN '%s': %v\n", trimmedEntry, resolveErr)
			continue
		}

		// Add all resolved IP addresses to the tracking list.
		for _, ip := range ips {
			trackedIPs[ip.String()] = struct{}{}
			resolvedIPs = append(resolvedIPs, ip.String())
		}
	}

	if len(trackedIPs) == 0 {
		log.Fatal("You didn't enter any valid IPs or resolvable FQDNs.")
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("Error finding network adapters:", err)
	}

	fmt.Println("\nAvailable network adapters:")
	for i, dev := range devices {
		description := dev.Description
		if description == "" {
			description = dev.Name
		}
		fmt.Printf("%d: %s\n", i, description)
	}
	fmt.Println()

	fmt.Print("Enter the number of the adapter to monitor: ")
	input, err = reader.ReadString('\n')
	if err != nil {
		log.Fatal("Error reading adapter choice:", err)
	}

	choice, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil || choice < 0 || choice >= len(devices) {
		log.Fatal("Invalid choice. Please enter a valid number.")
	}

	selectedDevice := devices[choice]
	fmt.Printf("Monitoring adapter: %s\n", selectedDevice.Description)
	fmt.Printf("Tracking resolved IPs: %v\n", resolvedIPs)
	fmt.Printf("Press Ctrl+C to stop.\n\n")

	if err := initCSVFile(); err != nil {
		log.Fatal(err)
	}

	// Ensure the CSV file is properly closed when exiting program
	defer func() {
		csvWriter.Flush()
		csvFile.Close()
		log.Println("Writing to CSV completed.")
	}()

	// Open the selected network device for packet capture
	handle, err := pcap.OpenLive(selectedDevice.Name, snapshotLenght, promiscuous, timeout)
	if err != nil {
		log.Fatalf("Error accessing adapter %s: %v", selectedDevice.Name, err)
	}
	defer handle.Close()

	// Start processing packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

// Initializing CSV file
func initCSVFile() error {
	var err error
	csvFile, err = os.Create(CSV)
	if err != nil {
		return fmt.Errorf("error creating CSV file: %w", err)
	}

	csvWriter = csv.NewWriter(csvFile)
	csvWriter.Comma = ';'

	headers := []string{"Timestamp", "IP", "Traffic", "Bytes"}
	if err := csvWriter.Write(headers); err != nil {
		return fmt.Errorf("error writing header to CSV: %w", err) // Go community is advising that error strings should not be capitalized
	}
	csvWriter.Flush()
	return nil
}
