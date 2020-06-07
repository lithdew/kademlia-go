package kademlia

import (
	"io"
	"unsafe"
)

const (
	SizeHandshakePacket = 2*SizePublicKey + SizeSignature
)

type HandshakePacket struct {
	Node      PublicKey
	Session   PublicKey
	Signature Signature
}

func (p HandshakePacket) AppendTo(dst []byte) []byte {
	dst = append(dst, p.Node[:]...)
	dst = append(dst, p.Session[:]...)
	dst = append(dst, p.Signature[:]...)
	return dst
}

func UnmarshalHandshakePacket(buf []byte) (HandshakePacket, error) {
	var packet HandshakePacket
	if len(buf) != SizeHandshakePacket {
		return packet, io.ErrUnexpectedEOF
	}
	packet.Node, buf = *(*PublicKey)(unsafe.Pointer(&((buf[:SizePublicKey])[0]))), buf[SizePublicKey:]
	packet.Session, buf = *(*PublicKey)(unsafe.Pointer(&((buf[:SizePublicKey])[0]))), buf[SizePublicKey:]
	packet.Signature, buf = *(*Signature)(unsafe.Pointer(&((buf[:SizeSignature])[0]))), buf[SizeSignature:]
	return packet, nil
}
