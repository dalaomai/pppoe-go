package main

import (
	"flag"

	"github.com/dalaomai/pppoe-go/packets"
)

var (
	device string
)

func main() {

	flag.StringVar(&device, "i", "eth1", "网卡名")
	flag.Parse()

	packets.BruteForcwPassword(device, "301")
}

// func getMACAddr() net.HardwareAddr {
// 	interfaces, _ := net.Interfaces()
// 	for _, netInterface := range interfaces {
// 		if netInterface.Name == device {
// 			return netInterface.HardwareAddr
// 		}
// 	}
// 	return net.HardwareAddr{0x80, 0x81, 0x00, 0xb7, 0x37, 0x81}
// 	// return net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
// 	// panic(fmt.Sprintf("device not found: %v", device))
// }
