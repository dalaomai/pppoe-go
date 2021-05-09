package packets

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"net"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type LCPCode uint8

var (
	LCPCodeConfigRequest    = LCPCode(0x01)
	LCPCodeConfigAck        = LCPCode(0x02)
	LCPCodeConfigNak        = LCPCode(0x03)
	LCPCodeConfigReject     = LCPCode(0x04)
	LCPCodeTerminateRequest = LCPCode(0x05)
	LCPCodeTerminateAck     = LCPCode(0x06)
	LCPCodeCodeReject       = LCPCode(0x07)
	LCPCodeProtocolReject   = LCPCode(0x08)
	LCPCodeEchoRequest      = LCPCode(0x09)
	LCPCodeEchoReplyt       = LCPCode(0x0a)
	LCPCodeDiscardRequest   = LCPCode(0x0b)
	LCPCodeReserved         = LCPCode(0x0c)

	LCPCodeNames = map[LCPCode]string{
		LCPCodeConfigRequest:    "LCPCodeConfigRequest",
		LCPCodeConfigAck:        "LCPCodeConfigAck",
		LCPCodeConfigNak:        "LCPCodeConfigNak",
		LCPCodeConfigReject:     "LCPCodeConfigReject",
		LCPCodeTerminateRequest: "LCPCodeTerminateRequest",
		LCPCodeTerminateAck:     "LCPCodeTerminateAck",
		LCPCodeCodeReject:       "LCPCodeCodeReject",
		LCPCodeProtocolReject:   "LCPCodeProtocolReject",
		LCPCodeEchoRequest:      "LCPCodeEchoRequest",
		LCPCodeEchoReplyt:       "LCPCodeEchoReplyt",
		LCPCodeDiscardRequest:   "LCPCodeDiscardRequest",
		LCPCodeReserved:         "LCPCodeReserved",
	}
)

type PAPCode uint8

var (
	PAPCodeRequest = PAPCode(0x01)
	PAPCodeAck     = PAPCode(0x02)
	PAPCodeNak     = PAPCode(0x03)
	PAPCodeNames   = map[PAPCode]string{
		PAPCodeRequest: "PAPAuthenticateRequest",
		PAPCodeAck:     "PAPAuthenticateAck",
		PAPCodeNak:     "PAPAuthenticateNak",
	}
)

type LCPTLVType uint8

var (
	MaxReceiveUnitType                = LCPTLVType(0x01)
	AsyncControlCharacterType         = LCPTLVType(0x02)
	AuthenticationProtocolType        = LCPTLVType(0x03)
	QualityProtocolType               = LCPTLVType(0x04)
	MagicNumberType                   = LCPTLVType(0x05)
	RESERVEDType                      = LCPTLVType(0x06)
	ProtocolFieldCompressionType      = LCPTLVType(0x07)
	AddressAndControlFieldCompression = LCPTLVType(0x08)

	LCPTLVTypeNames = map[LCPTLVType]string{
		MaxReceiveUnitType:                "MaxReceiveUnitType",
		AsyncControlCharacterType:         "AsyncControlCharacterType",
		AuthenticationProtocolType:        "AuthenticationProtocolType",
		QualityProtocolType:               "QualityProtocolType",
		MagicNumberType:                   "MagicNumberType",
		RESERVEDType:                      "RESERVEDType",
		ProtocolFieldCompressionType:      "ProtocolFieldCompressionType",
		AddressAndControlFieldCompression: "AddressAndControlFieldCompression",
	}
)

var (
	PPPTypeLCP  = layers.PPPType(0xc021)
	PPPTypePAP  = layers.PPPType(0xc023)
	PPPTypeCHAP = layers.PPPType(0xc223)

	PPPTypeNames = map[layers.PPPType]string{
		PPPTypePAP:  "PAP",
		PPPTypeCHAP: "CHAP",
	}
)

type LCP struct {
	Code       LCPCode
	Identifier uint8
	TLVMap     map[LCPTLVType][]byte
	Data       []byte
}

type PAP struct {
	Code       PAPCode
	Identifier uint8
	Username   string
	Password   string
	Message    string
	Data       []byte
}

func PareseLCP(payload []byte) (*LCP, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("error payload length for LCP parse %v", payload)
	}
	lcp := LCP{
		Code:       LCPCode(payload[0]),
		Identifier: payload[1],
	}
	dataByteLength := int(binary.BigEndian.Uint16(payload[2:4]))

	if len(payload) != dataByteLength {
		return nil, fmt.Errorf("error payload length for LCP parse %v", payload)
	}

	dataBytes := payload[4:]
	lcp.Data = dataBytes

	if lcp.Code == LCPCodeConfigRequest {
		tlvMap := make(map[LCPTLVType][]byte)
		for len(dataBytes) > 0 {
			if len(dataBytes) < 2 {
				return nil, fmt.Errorf("err to parse lcp tlv:%v", dataBytes)
			}
			t := LCPTLVType(dataBytes[0])
			l := int(dataBytes[1])
			if len(dataBytes) < l {
				return nil, fmt.Errorf("err to parse lcp tlv:%v", dataBytes)
			}

			v := dataBytes[2:l]
			tlvMap[t] = v

			dataBytes = dataBytes[l:]
		}
		lcp.TLVMap = tlvMap
	}

	return &lcp, nil
}

func ParesePAP(payload []byte) (*PAP, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("error payload length for PAP parse %v", payload)
	}
	pap := PAP{
		Code:       PAPCode(payload[0]),
		Identifier: payload[1],
	}
	dataByteLength := int(binary.BigEndian.Uint16(payload[2:4]))

	if len(payload) != dataByteLength {
		return nil, fmt.Errorf("error payload length for LCP parse %v", payload)
	}

	dataBytes := payload[4:]
	pap.Data = dataBytes

	if pap.Code == PAPCodeRequest {
		userLen := int(dataBytes[0])
		pap.Username = string(dataBytes[1 : 1+userLen])
		pwdLen := int(1 + userLen)
		pap.Password = string(dataBytes[2+userLen : 2+userLen+pwdLen])
	} else {
		l := int(dataBytes[0])
		pap.Message = string(dataBytes[1 : 1+l])
	}

	return &pap, nil
}

func (lcp *LCP) Encode() ([]byte, error) {
	if lcp.Data == nil && lcp.TLVMap == nil {
		return nil, fmt.Errorf("LCP Error not data provided to encode")
	}

	if lcp.Data == nil {
		tlvBytes := make([]byte, 0)
		for k, v := range lcp.TLVMap {
			tlvBytes = append(tlvBytes, uint8(k), uint8(1+1+len(v)))
			tlvBytes = bytes.Join([][]byte{tlvBytes, v}, []byte{})
		}
		lcp.Data = tlvBytes
	}

	payloadLength := make([]byte, 2)
	binary.BigEndian.PutUint16(payloadLength, uint16(1+1+2+len(lcp.Data)))

	payload := make([]byte, 0)
	payload = append(payload, uint8(lcp.Code), lcp.Identifier)
	payload = bytes.Join([][]byte{payload, payloadLength, lcp.Data}, []byte{})
	return payload, nil
}

func (lcp *LCP) String() string {
	codeName, ok := LCPCodeNames[lcp.Code]
	if !ok {
		codeName = fmt.Sprint(lcp.Code)
	}

	optionsStr := make(map[string]string)
	for t, v := range lcp.TLVMap {
		name, ok := LCPTLVTypeNames[t]
		if !ok {
			name = fmt.Sprint(t)
		}

		value := fmt.Sprint(v)
		if t == AuthenticationProtocolType {
			value_t, ok := PPPTypeNames[layers.PPPType(binary.BigEndian.Uint16(v[:2]))]
			if ok {
				value = value_t
			}
		}
		optionsStr[name] = fmt.Sprint(value)
	}

	return fmt.Sprintf(
		"Code:%v \n\tIdentifier:%v \n\tOptions:%v \n\tData:%v",
		codeName, lcp.Identifier, optionsStr, lcp.Data)
}

func (pap *PAP) String() string {
	codeName, ok := PAPCodeNames[pap.Code]
	if !ok {
		codeName = fmt.Sprint(pap.Code)
	}
	return fmt.Sprintf(
		"Code:%v \n\tIdentifier:%v \n\tUsername:%v \n\tPassword:%v \n\tMessage:%v",
		codeName, pap.Identifier, pap.Username, pap.Password, pap.Message)
}

func (pap *PAP) Encode() ([]byte, error) {

	if pap.Data == nil {
		dataBytes := make([]byte, 0)
		if pap.Code == PAPCodeRequest {
			usernameBytes := []byte(pap.Username)
			passwordBytes := []byte(pap.Password)

			dataBytes = append(dataBytes, uint8(len(usernameBytes)))
			dataBytes = bytes.Join([][]byte{dataBytes, usernameBytes}, []byte{})
			dataBytes = append(dataBytes, uint8(len(passwordBytes)))
			dataBytes = bytes.Join([][]byte{dataBytes, passwordBytes}, []byte{})
		} else {
			messageBytes := []byte(pap.Message)
			dataBytes = append(dataBytes, uint8(len(messageBytes)))
			dataBytes = bytes.Join([][]byte{dataBytes, messageBytes}, []byte{})
		}

		pap.Data = dataBytes
	}

	payloadLength := make([]byte, 2)
	binary.BigEndian.PutUint16(payloadLength, uint16(1+1+2+len(pap.Data)))

	payload := make([]byte, 0)
	payload = append(payload, uint8(pap.Code), pap.Identifier)
	payload = bytes.Join([][]byte{payload, payloadLength, pap.Data}, []byte{})
	return payload, nil
}

func (lcp *LCP) Send(pcapHandle *pcap.Handle, srcMAC net.HardwareAddr, dstMAC net.HardwareAddr, sessionid uint16) error {
	lcpBytes, err := lcp.Encode()
	if err != nil {
		return nil
	}

	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, uint16(PPPTypeLCP))
	payload = bytes.Join([][]byte{payload, lcpBytes}, []byte{})

	sendPPPoEPacket(pcapHandle, srcMAC, dstMAC, payload, layers.PPPoECodeSession, sessionid, layers.EthernetTypePPPoESession)
	return nil
}

func (pap *PAP) Send(pcapHandle *pcap.Handle, srcMAC net.HardwareAddr, dstMAC net.HardwareAddr, sessionid uint16) error {
	papBytes, err := pap.Encode()
	if err != nil {
		return nil
	}

	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, uint16(PPPTypePAP))
	payload = bytes.Join([][]byte{payload, papBytes}, []byte{})

	sendPPPoEPacket(pcapHandle, srcMAC, dstMAC, payload, layers.PPPoECodeSession, sessionid, layers.EthernetTypePPPoESession)
	return nil
}
