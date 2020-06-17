package main

import (
	"github.com/lithdew/kademlia"
	"github.com/lithdew/reliable"
	"log"
	"math"
	"net"
	"time"
)

func check(err error) {
	if err != nil {
		log.Panic(err)
	}
}

func readLoop(pc net.PacketConn, c *reliable.Conn) {
	var (
		n    int
		addr net.Addr
		err  error
	)

	buf := make([]byte, math.MaxUint16+1)
	for {
		n, addr, err = pc.ReadFrom(buf)
		if err != nil {
			break
		}
		header, buf, err := reliable.UnmarshalPacketHeader(buf[:n])
		if err == nil {
			err = c.Read(header, buf)
		}
		if err != nil {
			log.Printf("%s->%s: error occured (err=%q)", pc.LocalAddr(), addr, err)
		}
	}
}

func main() {
	log.SetFlags(0)

	pa, err := kademlia.NewProtocol()
	check(err)

	pb, err := kademlia.NewProtocol()
	check(err)

	ca, err := net.ListenPacket("udp", "127.0.0.1:0")
	check(err)

	cb, err := net.ListenPacket("udp", "127.0.0.1:0")
	check(err)

	pha := func(addr net.Addr, seq uint16, buf []byte) {
		check(pa.Read(buf, addr))
	}

	phb := func(addr net.Addr, seq uint16, buf []byte) {
		check(pb.Read(buf, addr))
	}

	a := reliable.NewConn(ca, cb.LocalAddr(), reliable.WithPacketHandler(pha))
	b := reliable.NewConn(cb, ca.LocalAddr(), reliable.WithPacketHandler(phb))

	go readLoop(ca, a)
	go readLoop(cb, b)

	go a.Run()
	go b.Run()

	log.Printf("A (addr=%q) (pub=%q) (priv=%q)", ca.LocalAddr(), pa.PublicKey(), pa.PrivateKey().Seed())
	log.Printf("B (addr=%q) (pub=%q) (priv=%q)", cb.LocalAddr(), pb.PublicKey(), pb.PrivateKey().Seed())

	defer func() {
		check(ca.SetDeadline(time.Now().Add(1 * time.Millisecond)))
		check(cb.SetDeadline(time.Now().Add(1 * time.Millisecond)))

		a.Close()
		b.Close()

		check(ca.Close())
		check(cb.Close())
	}()

	//pkt := kademlia.HandshakeRequest{
	//	Node:      pa.PublicKey(),
	//	Signature: pa.PrivateKey().Sign(append(kademlia.ZeroPublicKey[:], pa.hm...)),
	//}

	//check(a.WriteReliablePacket(pkt.AppendTo(nil)))

	time.Sleep(100 * time.Millisecond)
}
