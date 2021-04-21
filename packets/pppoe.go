package packets

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket/layers"
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
