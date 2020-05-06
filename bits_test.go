package main

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestLeadingZeros(t *testing.T) {
	tests := []struct {
		payload  []byte
		expected int
	}{
		{payload: []byte{0, 0, 0, 2}, expected: 30},
		{payload: []byte{0, 0, 1, 0}, expected: 23},
	}

	for _, test := range tests {
		require.EqualValues(t, test.expected, leadingZeros(test.payload))
	}
}
