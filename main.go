package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/dalaomai/pppoe-go/packets"
	"github.com/dalaomai/pppoe-go/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

var (
	device       string
	handle       *pcap.Handle
	snapshot_len int32         = 1024
	promiscuous  bool          = true
	timeout      time.Duration = -1 * time.Second
	err          error
	sessionID    uint16
)

var logger *logrus.Logger

func main() {
	logger = utils.GetLogger()
	stopChan := make(chan int)

	flag.StringVar(&device, "i", "eth1", "网卡名")
	flag.Parse()

	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		for packet := range packetSource.Packets() {
			handlePacket(packet)
		}
	}()

	hostUniq := rand.Uint32()
	logger.Printf("host uniq %v\n", hostUniq)
	sendPADI(getMACAddr(), hostUniq)

	<-stopChan
}

func handlePacket(packet gopacket.Packet) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		logger.Warningf("not a ethernet packet:%v", packet)
		return
	}
	ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
	srcMAC := ethernetPacket.SrcMAC
	dstMAC := ethernetPacket.DstMAC
	ethernetType := ethernetPacket.EthernetType
	logger.Infof("%v -> %v  %v\n", srcMAC, dstMAC, ethernetType)

	switch ethernetType {
	case layers.EthernetTypePPPoEDiscovery:
		packet, err := decodePPPoePacket(packet)
		if err != nil {
			logger.Error(err)
			return
		}
		switch packet.Packet.Code {
		case layers.PPPoECodePADO:
			err = sendPADR(getMACAddr(), srcMAC, *packet)
			if err != nil {
				logger.Error(err)
				return
			}
		case layers.PPPoECodePADS:
			sessionID = packet.Packet.SessionId
			logger.Infof("Get the Session:% v", sessionID)
		default:
			logger.Warn(packet)
		}
	case layers.EthernetTypePPPoESession:
		decodePPPoePacket(packet)
		logger.Info(packet)
	default:
	}

}

func decodePPPoePacket(packet gopacket.Packet) (*packets.PPPoE, error) {
	pppoeLayer := packet.Layer(layers.LayerTypePPPoE)
	if pppoeLayer == nil {
		return nil, fmt.Errorf("not a pppoe packet: %v", pppoeLayer)
	}
	pppoePacket_, _ := pppoeLayer.(*layers.PPPoE)
	if pppoePacket_ == nil {
		return nil, fmt.Errorf("decode pppoe err")
	}
	pppoePacket := &packets.PPPoE{
		Packet: *pppoePacket_,
	}
	err = pppoePacket.ParseTLV()

	return pppoePacket, err
}

func getMACAddr() net.HardwareAddr {
	interfaces, _ := net.Interfaces()
	for _, netInterface := range interfaces {
		if netInterface.Name == device {
			return netInterface.HardwareAddr
		}
	}
	panic(fmt.Sprintf("device not found: %v", device))
}

func sendPADI(srcMAC net.HardwareAddr, hostUniq uint32) {

	hostUniqBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(hostUniqBytes, hostUniq)

	SNTLV := packets.CreateTLVBytes(
		packets.TLVType(packets.ServiceNameType), []byte{})
	HUTLV := packets.CreateTLVBytes(
		packets.TLVType(packets.HostUniqType), hostUniqBytes)
	payload := bytes.Join([][]byte{SNTLV, HUTLV}, []byte{})

	sendPacket(
		srcMAC,
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		payload,
		layers.PPPoECodePADI,
		0x0000,
		layers.EthernetTypePPPoEDiscovery,
	)
}

func sendPADR(srcMAC net.HardwareAddr, dstMAC net.HardwareAddr, PADOPack packets.PPPoE) error {
	huv, ok := PADOPack.TLVMap[packets.HostUniqType]
	if !ok {
		return fmt.Errorf("pado pack not have hu : %v", PADOPack)
	}

	SNTLV := packets.CreateTLVBytes(
		packets.TLVType(packets.ServiceNameType), []byte{})
	HUTLV := packets.CreateTLVBytes(packets.TLVType(packets.HostUniqType), huv)
	payload := bytes.Join([][]byte{SNTLV, HUTLV}, []byte{})

	if cookie, ok := PADOPack.TLVMap[packets.ACCookieType]; ok {
		CookieTLV := packets.CreateTLVBytes(packets.TLVType(packets.ACCookieType), cookie)
		payload = bytes.Join([][]byte{payload, CookieTLV}, []byte{})
	}

	sendPacket(
		srcMAC,
		dstMAC,
		payload,
		layers.PPPoECodePADR,
		0x0000,
		layers.EthernetTypePPPoEDiscovery,
	)
	return nil
}

func sendPacket(srcMAC net.HardwareAddr, dstMAC net.HardwareAddr, payload []byte, code layers.PPPoECode, sessionid uint16, protocol layers.EthernetType) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}

	gopacket.SerializeLayers(
		buffer, options,
		&layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: protocol,
		},
		&layers.PPPoE{
			Version:   uint8(1),
			Type:      uint8(1),
			Code:      code,
			SessionId: sessionid,
			Length:    uint16(len(payload)),
		},
		gopacket.Payload(payload),
	)

	handle.WritePacketData(buffer.Bytes())
}
