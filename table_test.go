package kademlia

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func genKeys(t testing.TB) (PublicKey, PrivateKey) {
	t.Helper()
	pub, sec, err := GenerateKeys(nil)
	require.NoError(t, err)
	return pub, sec
}

func genPub(t testing.TB) PublicKey {
	t.Helper()
	pub, _ := genKeys(t)
	return pub
}

//func TestTable(t *testing.T) {
//	id := ID{Pub: genPub(t)}
//	table := NewTable(id)
//
//	for i := 0; i < 100; i++ {
//		table.Update(ID{Pub: genPub(t)})
//	}
//
//	require.EqualValues(t, table.Len(), 100)
//}
