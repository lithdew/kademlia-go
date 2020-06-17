package kademlia

import (
	"bytes"
	"github.com/lithdew/bytesutil"
	"math/bits"
	"sort"
)

func leadingZeros(buf []byte) (count int) {
	for i := range buf {
		b := buf[i]
		if b != 0 {
			return i*8 + bits.LeadingZeros8(b)
		}
	}
	return len(buf) * 8
}

func xor(dst, a, b []byte) []byte {
	s := len(a)
	if sb := len(b); sb < s {
		s = sb
	}
	dst = bytesutil.ExtendSlice(dst, s)
	for i := 0; i < s; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return dst
}

func SortIDs(pub PublicKey, ids []ID) []ID {
	dst := func(idx int) []byte { return xor(nil, ids[idx].Pub[:], pub[:]) }
	cmp := func(i, j int) bool { return bytes.Compare(dst(i), dst(j)) == -1 }
	sort.Slice(ids, cmp)
	return ids
}
