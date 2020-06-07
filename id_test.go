package kademlia

import (
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGeneratePuzzleKeys(t *testing.T) {
	pub, priv, err := GeneratePuzzleKeys(nil, 10)
	require.NoError(t, err)
	spew.Dump(pub, priv)
}
