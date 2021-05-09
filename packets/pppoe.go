package packets

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PPPoETLVType TLVType

var (
	ServiceNameType = PPPoETLVType(0x0101)
	ACNameType      = PPPoETLVType(0x0102)
	HostUniqType    = PPPoETLVType(0x0103)
	ACCookieType    = PPPoETLVType(0x0104)

	PPPoETLVNames = map[PPPoETLVType]string{
		ServiceNameType: "Service-Name",
		ACNameType:      "AC-Name",
		HostUniqType:    "Host-Uniq",
		ACCookieType:    "AC-Cookie",
	}
)

var PPPoECodeNames = map[layers.PPPoECode]string{
	layers.PPPoECodePADI:    "PADI",
	layers.PPPoECodePADO:    "PADO",
	layers.PPPoECodePADR:    "PADR",
	layers.PPPoECodePADS:    "PADS",
	layers.PPPoECodePADT:    "PADT",
	layers.PPPoECodeSession: "Session",
}

type PPPoE struct {
	Packet layers.PPPoE
	TLVMap map[PPPoETLVType][]byte
}

func DecodePPPoePacket(packet gopacket.Packet) (*PPPoE, error) {
	pppoeLayer := packet.Layer(layers.LayerTypePPPoE)
	if pppoeLayer == nil {
		return nil, fmt.Errorf("not a pppoe packet: %v", pppoeLayer)
	}
	pppoePacket_, _ := pppoeLayer.(*layers.PPPoE)
	if pppoePacket_ == nil {
		return nil, fmt.Errorf("decode pppoe err")
	}
	pppoePacket := &PPPoE{
		Packet: *pppoePacket_,
	}
	err := pppoePacket.ParseTLV()

	return pppoePacket, err
}

func (p *PPPoE) ParseTLV() error {
	TLVBytes := p.Packet.Payload
	tlvMap := make(map[PPPoETLVType][]byte)

	for len(TLVBytes) > 0 {
		if len(TLVBytes) < 4 {
			return fmt.Errorf("err to parse tlv:%v", TLVBytes)
		}
		t := binary.BigEndian.Uint16(TLVBytes[:2])
		l := int(binary.BigEndian.Uint16(TLVBytes[2:4]))
		if len(TLVBytes) < (4 + l) {
			return fmt.Errorf("err to parse tlv.len:%v  data :%v", l, TLVBytes)
		}

		v := TLVBytes[4 : 4+l]
		tlvMap[PPPoETLVType(t)] = v

		TLVBytes = TLVBytes[4+l:]
	}

	p.TLVMap = tlvMap
	return nil
}

func (p *PPPoE) String() string {
	tlvStrng := make(map[string]string)
	for t, v := range p.TLVMap {
		name, ok := PPPoETLVNames[t]
		if !ok {
			name = fmt.Sprintf("unknow %v", int(t))
		}
		tlvStrng[name] = fmt.Sprint(v)
	}

	codeName, ok := PPPoECodeNames[p.Packet.Code]
	if !ok {
		codeName = fmt.Sprint(int(p.Packet.Code))
	}

	return fmt.Sprintf(
		"session-id:%v \n\tcode:%v \n\tpayload: %v",
		p.Packet.SessionId, codeName, tlvStrng)
}

func sendPPPoEPacket(pcapHandle *pcap.Handle, srcMAC net.HardwareAddr, dstMAC net.HardwareAddr, payload []byte, code layers.PPPoECode, sessionid uint16, protocol layers.EthernetType) {
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

	pcapHandle.WritePacketData(buffer.Bytes())
}

func SendPADI(pcapHandle *pcap.Handle, srcMAC net.HardwareAddr, hostUniq uint32) {

	hostUniqBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(hostUniqBytes, hostUniq)

	SNTLV := CreateTLVBytes(
		TLVType(ServiceNameType), []byte{})
	HUTLV := CreateTLVBytes(
		TLVType(HostUniqType), hostUniqBytes)
	payload := bytes.Join([][]byte{SNTLV, HUTLV}, []byte{})

	sendPPPoEPacket(
		pcapHandle,
		srcMAC,
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		payload,
		layers.PPPoECodePADI,
		0x0000,
		layers.EthernetTypePPPoEDiscovery,
	)
}

func SendPADR(pcapHandle *pcap.Handle, srcMAC net.HardwareAddr, dstMAC net.HardwareAddr, PADOPack PPPoE) error {
	huv, ok := PADOPack.TLVMap[HostUniqType]
	if !ok {
		return fmt.Errorf("pado pack not have hu : %v", PADOPack)
	}

	SNTLV := CreateTLVBytes(
		TLVType(ServiceNameType), []byte{})
	HUTLV := CreateTLVBytes(TLVType(HostUniqType), huv)
	payload := bytes.Join([][]byte{SNTLV, HUTLV}, []byte{})

	if cookie, ok := PADOPack.TLVMap[ACCookieType]; ok {
		CookieTLV := CreateTLVBytes(TLVType(ACCookieType), cookie)
		payload = bytes.Join([][]byte{payload, CookieTLV}, []byte{})
	}

	sendPPPoEPacket(
		pcapHandle,
		srcMAC,
		dstMAC,
		payload,
		layers.PPPoECodePADR,
		0x0000,
		layers.EthernetTypePPPoEDiscovery,
	)
	return nil
}
