package kademlia

import "container/list"

const (
	SizeTable         = SizePublicKey * 8
	DefaultBucketSize = 16
)

type Table struct {
	id  ID  // node id
	cap int // capacity of peer id bucket
	len int // number of peer ids stored

	bkts [SizeTable]*list.List // peer id buckets
}

func NewTable(id ID) *Table {
	t := &Table{id: id}
	for i := range t.bkts {
		t.bkts[i] = list.New()
	}
	if t.cap == 0 {
		t.cap = DefaultBucketSize
	}
	return t
}

func (t *Table) bucketIndex(pub PublicKey) int {
	return leadingZeros(xor(nil, pub[:], t.id.Pub[:]))
}

func (t *Table) Len() int {
	return t.len
}

func (t *Table) Update(id ID) {
	if t.id.Pub == id.Pub {
		return
	}
	bkt := t.bkts[t.bucketIndex(id.Pub)]
	for e := bkt.Front(); e != nil; e = e.Next() {
		if e.Value.(ID).Pub == id.Pub {
			bkt.MoveToFront(e)
			return
		}
	}
	if bkt.Len() < t.cap {
		bkt.PushFront(id)
		t.len++
		return
	}
	return
}

func (t *Table) ClosestTo(pub PublicKey, k int) []ID {
	if k > t.len {
		k = t.len
	}

	closest := make([]ID, 0, k)

	fill := func(i int) bool {
		for e := t.bkts[i].Front(); len(closest) < k && e != nil; e = e.Next() {
			if id := e.Value.(ID); id.Pub != pub {
				closest = append(closest, id)
			}
		}
		return len(closest) < k
	}

	m := t.bucketIndex(pub)
	l, r := m-1, m+1

	fill(m)
	for (l >= 0 && fill(l)) || (r < len(t.bkts) && fill(r)) {
		l, r = l-1, r+1
	}

	return SortIDs(t.id, closest)
}
