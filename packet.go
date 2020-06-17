package kademlia

import (
	"fmt"
	"io"
	"unsafe"
)

const (
	SizeHandshakeRequest = 2*SizePublicKey + SizeSignature
	SizeFindNodeRequest  = SizePublicKey
)

type HandshakeRequest struct {
	PublicKey  PublicKey `json:"public_key"`
	SessionKey PublicKey `json:"session_key"`
	Signature  Signature `json:"signature"`
}

func (p HandshakeRequest) AppendTo(dst []byte) []byte {
	dst = append(dst, p.PublicKey[:]...)
	dst = append(dst, p.SessionKey[:]...)
	dst = append(dst, p.Signature[:]...)
	return dst
}

func UnmarshalHandshakeRequest(buf []byte) (HandshakeRequest, []byte, error) {
	var packet HandshakeRequest
	if len(buf) < SizeHandshakeRequest {
		return packet, buf, io.ErrUnexpectedEOF
	}
	packet.PublicKey, buf = *(*PublicKey)(unsafe.Pointer(&((buf[:SizePublicKey])[0]))),
		buf[SizePublicKey:]
	packet.SessionKey, buf = *(*PublicKey)(unsafe.Pointer(&((buf[:SizePublicKey])[0]))),
		buf[SizePublicKey:]
	packet.Signature, buf = *(*Signature)(unsafe.Pointer(&((buf[:SizeSignature])[0]))),
		buf[SizeSignature:]
	return packet, buf, nil
}

type FindNodeRequest struct {
	Target PublicKey `json:"public_key"`
}

func (r FindNodeRequest) AppendTo(dst []byte) []byte { return append(dst, r.Target[:]...) }

func UnmarshalFindNodeRequest(buf []byte) (FindNodeRequest, []byte, error) {
	var packet FindNodeRequest
	if len(buf) < SizeFindNodeRequest {
		return packet, buf, io.ErrUnexpectedEOF
	}
	packet.Target, buf = *(*PublicKey)(unsafe.Pointer(&((buf[:SizePublicKey])[0]))),
		buf[SizePublicKey:]
	return packet, buf, nil
}

type FindNodeResponse struct {
	Closest []ID `json:"closest"`
}

func (r FindNodeResponse) AppendTo(dst []byte) []byte {
	dst = append(dst, byte(len(r.Closest)))
	for _, id := range r.Closest {
		dst = id.AppendTo(dst)
	}
	return dst
}

func UnmarshalFindNodeResponse(buf []byte) (FindNodeResponse, []byte, error) {
	var packet FindNodeResponse
	if len(buf) < 1 {
		return packet, buf, io.ErrUnexpectedEOF
	}

	packet.Closest, buf = make([]ID, 0, buf[0]), buf[1:]

	var (
		id  ID
		err error
	)

	for i := 0; i < cap(packet.Closest); i++ {
		id, buf, err = UnmarshalID(buf)
		if err != nil {
			return packet, buf, fmt.Errorf("failed to decode id: %w", err)
		}
		packet.Closest = append(packet.Closest, id)
	}

	return packet, buf, nil
}
