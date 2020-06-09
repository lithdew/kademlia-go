package kademlia

import (
	"io"
	"unsafe"
)

const (
	SizeHandshakePacket = 2*SizePublicKey + SizeSignature
)

type HandshakePacket struct {
	PublicKey  PublicKey `json:"public_key"`
	SessionKey PublicKey `json:"session_key"`
	Signature  Signature `json:"signature"`
}

func (p HandshakePacket) AppendTo(dst []byte) []byte {
	dst = append(dst, p.PublicKey[:]...)
	dst = append(dst, p.SessionKey[:]...)
	dst = append(dst, p.Signature[:]...)
	return dst
}

func UnmarshalHandshakePacket(buf []byte) (HandshakePacket, error) {
	var packet HandshakePacket
	if len(buf) != SizeHandshakePacket {
		return packet, io.ErrUnexpectedEOF
	}
	packet.PublicKey, buf = *(*PublicKey)(unsafe.Pointer(&((buf[:SizePublicKey])[0]))),
		buf[SizePublicKey:]
	packet.SessionKey, buf = *(*PublicKey)(unsafe.Pointer(&((buf[:SizePublicKey])[0]))),
		buf[SizePublicKey:]
	packet.Signature, buf = *(*Signature)(unsafe.Pointer(&((buf[:SizeSignature])[0]))),
		buf[SizeSignature:]
	return packet, nil
}
