package kademlia

import (
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/rand"
	"net"
	"testing"
	"testing/quick"
)

func TestGeneratePuzzleKeys(t *testing.T) {
	pub, priv, err := GeneratePuzzleKeys(nil, 10)
	require.NoError(t, err)
	spew.Dump(pub, priv)
}

func TestHandshakePacket(t *testing.T) {
	var buf []byte

	f := func(expected HandshakeRequest) bool {
		actual, buf, err := UnmarshalHandshakeRequest(expected.AppendTo(buf[:0]))
		return assert.EqualValues(t, expected, actual) && assert.Len(t, buf, 0) && assert.NoError(t, err)
	}

	require.NoError(t, quick.Check(f, nil))
}

func TestID(t *testing.T) {
	var buf []byte

	f := func(expected ID) bool {
		if rand.Intn(1) == 0 {
			expected.Host = make([]byte, net.IPv4len)
		} else {
			expected.Host = make([]byte, net.IPv6len)
		}
		actual, _, err := UnmarshalID(expected.AppendTo(buf[:0]))
		return assert.EqualValues(t, expected, actual) && assert.NoError(t, err)
	}

	require.NoError(t, quick.Check(f, nil))
}
