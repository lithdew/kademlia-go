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

func genBucketPub(t testing.TB, table *Table, idx int) PublicKey {
	t.Helper()
	for {
		pub := genPub(t)
		if table.bucketIndex(pub) != idx {
			continue
		}
		return pub
	}
}

func TestTable(t *testing.T) {
	id := ID{Pub: genPub(t)}
	table := NewTable(id)

	for bucket := 0; bucket < 2; bucket++ {
		ids := make([]ID, 0, table.cap)
		for i := 0; i < table.cap; i++ {
			id := ID{Pub: genBucketPub(t, table, bucket)}
			ids = append(ids, id)

			require.EqualValues(t, UpdateNew, table.Update(id))
		}

		require.EqualValues(t, table.cap, table.buckets[bucket].Len())
		for _, id := range ids {
			require.True(t, table.Has(id.Pub))
		}

		require.ElementsMatch(t, ids, table.ClosestTo(table.id.Pub, table.cap))

		for _, id := range ids {
			require.True(t, table.Delete(id.Pub))
		}
		require.EqualValues(t, 0, table.buckets[bucket].Len())
	}
}
