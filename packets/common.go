package packets

import (
	"bytes"
	"encoding/binary"
)

type TLVType uint16

func CreateTLVBytes(typeInt TLVType, valueBytes []byte) []byte {
	typeUint := uint16(typeInt)

	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, typeUint)

	lengBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengBytes, uint16(len(valueBytes)))

	return bytes.Join([][]byte{typeBytes, lengBytes, valueBytes}, []byte{})

}
