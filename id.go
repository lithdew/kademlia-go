package kademlia

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/lithdew/bytesutil"
	"github.com/oasislabs/ed25519"
	"golang.org/x/crypto/blake2b"
	"io"
	"net"
	"unsafe"
)

const (
	SizePublicKey  = ed25519.PublicKeySize
	SizePrivateKey = ed25519.PrivateKeySize
	SizeSeed       = ed25519.SeedSize
	SizeSignature  = ed25519.SignatureSize

	SizeNodeID = 32
	SizeX      = SizeNodeID

	MinSizeID = SizePublicKey + 1 + net.IPv4len + 2
	MaxSizeID = SizePublicKey + 1 + net.IPv6len + 2
)

type (
	PublicKey  [SizePublicKey]byte
	PrivateKey [SizePrivateKey]byte
	Seed       [SizeSeed]byte
	Signature  [SizeSignature]byte

	NodeID [SizeNodeID]byte
	X      [SizeX]byte
)

var (
	ZeroPublicKey  PublicKey
	ZeroPrivateKey PrivateKey
	ZeroSeed       Seed
	ZeroSignature  Signature

	ZeroNodeID NodeID
	ZeroX      X
)

type ID struct {
	Pub  PublicKey `json:"public_key"`
	Host net.IP    `json:"host"`
	Port uint16    `json:"port"`
}

func (h ID) Validate() error {
	if len(h.Host) != net.IPv4len && len(h.Host) != net.IPv6len {
		return fmt.Errorf("node host is not valid ipv4 or ipv6: host ip is %d byte(s)", len(h.Host))
	}
	if h.Port == 0 {
		return errors.New("node port cannot be 0")
	}
	return nil
}

func (id ID) AppendTo(dst []byte) []byte {
	dst = append(dst, id.Pub[:]...)
	if len(id.Host) == net.IPv4len {
		dst = append(dst, 0)
	} else {
		dst = append(dst, 1)
	}
	dst = append(dst, id.Host...)
	dst = bytesutil.AppendUint16BE(dst, id.Port)
	return dst
}

func UnmarshalID(buf []byte) (ID, []byte, error) {
	var id ID
	if len(buf) < MinSizeID {
		return id, buf, io.ErrUnexpectedEOF
	}
	id.Pub, buf = *(*PublicKey)(unsafe.Pointer(&((buf[:SizePublicKey])[0]))), buf[SizePublicKey:]
	ipv4, buf := buf[0] == 0, buf[1:]
	if (ipv4 && len(buf) < net.IPv4len+2) || (!ipv4 && len(buf) < net.IPv6len+2) {
		return id, buf, io.ErrUnexpectedEOF
	}
	if ipv4 {
		id.Host, buf = buf[:net.IPv4len], buf[net.IPv4len:]
	} else {
		id.Host, buf = buf[:net.IPv6len], buf[net.IPv6len:]
	}
	id.Port, buf = bytesutil.Uint16BE(buf[:2]), buf[2:]
	return id, buf, nil
}

// GeneratePuzzleKeys takes O(2^c1).
func GeneratePuzzleKeys(r io.Reader, c1 int) (pub PublicKey, priv PrivateKey, err error) {
	for {
		pub, priv, err = GenerateKeys(r)
		if err != nil {
			return pub, priv, fmt.Errorf("failed to generate keys in static puzzle: %w", err)
		}
		if pub.NodeID().Valid(c1) {
			break
		}
	}
	return pub, priv, err
}

func GenerateKeys(r io.Reader) (publicKey PublicKey, privateKey PrivateKey, err error) {
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return publicKey, privateKey, err
	}
	publicKey = *(*PublicKey)(unsafe.Pointer(&pub[0]))
	privateKey = *(*PrivateKey)(unsafe.Pointer(&priv[0]))
	return publicKey, privateKey, err
}

func (p PrivateKey) String() string    { return hex.EncodeToString(p[:]) }
func (p PrivateKey) Zero() bool        { return p == ZeroPrivateKey }
func (p PrivateKey) Seed() Seed        { return *(*Seed)(unsafe.Pointer(&((p[:SizeSeed])[0]))) }
func (p PrivateKey) Public() PublicKey { return *(*PublicKey)(unsafe.Pointer(&((p[SizeSeed:])[0]))) }

func (p PrivateKey) Sign(buf []byte) Signature {
	signature, _ := (ed25519.PrivateKey)(p[:]).Sign(nil, buf, crypto.Hash(0))
	return *(*Signature)(unsafe.Pointer(&signature[0]))
}

func (s Seed) String() string { return hex.EncodeToString(s[:]) }
func (s Seed) Zero() bool     { return s == ZeroSeed }

func (s Signature) String() string { return hex.EncodeToString(s[:]) }
func (s Signature) Zero() bool     { return s == ZeroSignature }

func (s Signature) Verify(pub PublicKey, msg []byte) bool {
	return !s.Zero() && ed25519.Verify(pub[:], msg, s[:])
}

func (p PublicKey) String() string { return hex.EncodeToString(p[:]) }
func (p PublicKey) Zero() bool     { return p == ZeroPublicKey }
func (p PublicKey) NodeID() NodeID { return blake2b.Sum256(p[:]) }

func (p PublicKey) Verify(msg []byte, s Signature) bool {
	return !s.Zero() && ed25519.Verify(p[:], msg, s[:])
}

func (id NodeID) String() string    { return hex.EncodeToString(id[:]) }
func (id NodeID) Zero() bool        { return id == ZeroNodeID }
func (id NodeID) Valid(c1 int) bool { p := blake2b.Sum256(id[:]); return leadingZeros(p[:]) >= c1 }

// GenerateX takes O(2^c2).
func (id NodeID) GenerateX(r io.Reader, c2 int) (x X, err error) {
	for {
		_, err = io.ReadFull(r, x[:])
		if err != nil {
			return x, fmt.Errorf("failed to generate 'x' in dynamic puzzle: %w", err)
		}
		if x.Valid(id, c2) {
			break
		}
	}
	return x, err
}

func (x X) String() string               { return hex.EncodeToString(x[:]) }
func (x X) Zero() bool                   { return x == ZeroX }
func (x X) Valid(id NodeID, c2 int) bool { return leadingZeros(xor(nil, id[:], x[:])) >= c2 }
