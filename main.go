package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"

	"github.com/dalaomai/pppoe-go/packets"
	"github.com/dalaomai/pppoe-go/utils"
	"github.com/sirupsen/logrus"
)

var (
	device string
)

var logger *logrus.Logger

func main() {

	logger = utils.GetLogger()
	result := make(chan packets.PAP)

	flag.StringVar(&device, "i", "eth1", "网卡名")
	flag.Parse()

	go func() {
		for i := 999; i < 10000; i++ {
			go packets.PAPLoginSession(device, getRandomAddr(), "401", fmt.Sprint(i), result)
		}
	}()

	for pap := range result {
		logger.Infof("%v %v %v", pap.Username, pap.Password, pap.Message)
	}

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

func getRandomAddr() net.HardwareAddr {
	return net.HardwareAddr{byte(rand.Uint32()), byte(rand.Uint32()), byte(rand.Uint32()), byte(rand.Uint32()), byte(rand.Uint32()), byte(rand.Uint32())}
}
