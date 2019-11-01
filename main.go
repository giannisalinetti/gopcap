// All material is licensed under the Apache License Version 2.0, January 2004
// http://www.apache.org/licenses/LICENSE-2.0

// gopcap is a simple program that captures and dumps informations about
// network packets in the style of tcpdump. It is based on the package
// github.com/google/gopacket.
package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"log"
	"net"
)

// firstActiveInterface finds the first interface with an active IPv4 address
func firstActiveInterface() (*net.Interface, *net.IPNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, iface := range ifaces {
		var addr *net.IPNet
		if addrs, err := iface.Addrs(); err != nil {
			return nil, nil, err
		} else {
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok {
					if ip4 := ipnet.IP.To4(); ip4 != nil {
						addr = &net.IPNet{
							IP:   ip4,
							Mask: ipnet.Mask[len(ipnet.Mask)-4:],
						}
						// Omit loopback interface
						if addr.IP[0] == 127 {
							continue
						}
						return &iface, addr, nil
					}
				}
			}
		}
	}
	return nil, nil, fmt.Errorf("Cannot find active interfaces")
}

// packetDump outputs the packets including hex dump
func packetDump(ps *gopacket.PacketSource) error {
	for {
		packet, err := ps.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		fmt.Println(packet.Dump())
	}
	return nil
}

// packetString outputs the packets in a human-readable way
func packetString(ps *gopacket.PacketSource) error {
	for {
		packet, err := ps.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		fmt.Println(packet.String())
	}
	return nil
}

// tcpStat dumps a dynamic tcp statistics output
func tcpStat(ps *gopacket.PacketSource) error {
	for {
		packet, err := ps.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if ipv4layer := packet.Layer(layers.LayerTypeIPv4); ipv4layer != nil {
			ipv4, _ := ipv4layer.(*layers.IPv4) // IPv4 type assertion
			if tcplayer := packet.Layer(layers.LayerTypeTCP); tcplayer != nil {
				tcp, _ := tcplayer.(*layers.TCP) // TCP type assertion
				fmt.Printf("Source address: %s\tSource port: %d\tDest address: %s\tDest port: %d\n", ipv4.SrcIP, tcp.SrcPort, ipv4.DstIP, tcp.DstPort)
			}
		}
	}
	return nil
}

// udpStat dumps a dynamic tcp statistics output
func udpStat(ps *gopacket.PacketSource) error {
	for {
		packet, err := ps.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if ipv4layer := packet.Layer(layers.LayerTypeIPv4); ipv4layer != nil {
			ipv4, _ := ipv4layer.(*layers.IPv4) // IPv4 type assertion
			if udplayer := packet.Layer(layers.LayerTypeUDP); udplayer != nil {
				udp, _ := udplayer.(*layers.UDP) // UDP type assertion
				fmt.Printf("Source address: %s\tSource port: %d\tDest address: %s\tDest port: %d\n", ipv4.SrcIP, udp.SrcPort, ipv4.DstIP, udp.DstPort)
			}
		}
	}
	return nil
}

func main() {
	// Assign first usable interface
	firstIface, firstIfaceAddr, err := firstActiveInterface()
	if err != nil {
		log.Fatal(err)
	}

	// Define flags
	ifaceFlag := flag.String("i", firstIface.Name, "Default interface")
	snapLenFlag := flag.Int("s", 65536, "Snapshot length to read for each packet")
	promiscFlag := flag.Bool("p", false, "Set promiscuous mode")
	outputFlag := flag.String("o", "short", "Output mode (dump, short, tcpstat, udpstat)")
	flag.Parse()

	// Create a packet handle on a live interface
	handle, err := pcap.OpenLive(*ifaceFlag, int32(*snapLenFlag), *promiscFlag, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Create a new PacketSource from the handle
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	switch *outputFlag {
	case "dump":
		log.Printf("Started listening in dump mode on interface: %s, address: %s\n", *ifaceFlag, firstIfaceAddr.IP)
		err := packetDump(packetSource)
		if err != nil {
			log.Fatal(err)
		}
	case "short":
		log.Printf("Started listening in short mode on interface: %s, address: %s\n", *ifaceFlag, firstIfaceAddr.IP)
		err := packetString(packetSource)
		if err != nil {
			log.Fatal(err)
		}
	case "tcpstat":
		log.Printf("Started listening in tcpstat mode on interface: %s, address: %s\n", *ifaceFlag, firstIfaceAddr.IP)
		err := tcpStat(packetSource)
		if err != nil {
			log.Fatal(err)
		}
	case "udpstat":
		log.Printf("Started listening in udpstat mode on interface: %s, address: %s\n", *ifaceFlag, firstIfaceAddr.IP)
		err := udpStat(packetSource)
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("Error: unavailable output mode")
	}
}
