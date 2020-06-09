package kademlia

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"net"
)

const (
	DefaultC1 = 10
	DefaultC2 = 10
)

type Protocol struct {
	c1 int // s/kademlia static puzzle c1
	c2 int // s/kademlia dynamic puzzle c2

	pub  PublicKey  // node public key
	priv PrivateKey // node private key

	id    ID     // node id
	table *Table // node routing table

	setup bool // have we already handshaked with this peer?
}

func (p Protocol) PublicKey() PublicKey   { return p.pub }
func (p Protocol) PrivateKey() PrivateKey { return p.priv }

func NewProtocol() (*Protocol, error) {
	p := &Protocol{}
	if p.c1 == 0 {
		p.c1 = DefaultC1
	}
	if p.c2 == 0 {
		p.c2 = DefaultC2
	}
	if !p.priv.Zero() && p.pub.Zero() {
		p.pub = p.priv.Public()
	}
	if p.priv.Zero() {
		pub, priv, err := GeneratePuzzleKeys(nil, p.c1)
		if err != nil {
			return nil, err
		}
		p.pub = pub
		p.priv = priv
	}
	p.id = ID{Pub: p.pub}
	p.table = NewTable(p.id)
	return p, nil
}

func (p *Protocol) Read(buf []byte, addr net.Addr) error {
	if !p.setup {
		packet, err := UnmarshalHandshakePacket(buf)
		if err != nil {
			return err
		}
		return p.Handshake(packet, addr)
	}

	return nil
}

func (p *Protocol) Handshake(packet HandshakePacket, addr net.Addr) error {
	spew.Dump(packet)
	if !packet.Signature.Verify(packet.PublicKey, packet.SessionKey[:]) {
		return fmt.Errorf("%s: invalid signature on handshake packet", addr)
	}
	p.setup = true
	return nil
}
