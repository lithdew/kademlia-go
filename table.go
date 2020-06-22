package kademlia

import "container/list"

const (
	SizeTable         = SizePublicKey * 8
	DefaultBucketSize = 16
)

type Table struct {
	pub PublicKey
	cap int // capacity of peer id bucket
	len int // number of peer ids stored

	buckets [SizeTable]*list.List // peer id buckets
}

func NewTable(id PublicKey) *Table {
	t := &Table{pub: id}
	for i := range t.buckets {
		t.buckets[i] = list.New()
	}
	if t.cap == 0 {
		t.cap = DefaultBucketSize
	}
	return t
}

func (t Table) bucketIndex(pub PublicKey) int {
	if pub == t.pub {
		return 0
	}
	return leadingZeros(xor(nil, pub[:], t.pub[:]))
}

type UpdateResult int

const (
	UpdateNew UpdateResult = iota
	UpdateOk
	UpdateFull
	UpdateFail
)

// O(bucket_size) complexity.
func (t *Table) Update(id ID) UpdateResult {
	if t.pub == id.Pub {
		return UpdateFail
	}
	bucket := t.buckets[t.bucketIndex(id.Pub)]
	for e := bucket.Front(); e != nil; e = e.Next() {
		if e.Value.(ID).Pub == id.Pub {
			bucket.MoveToFront(e)
			return UpdateOk
		}
	}
	if bucket.Len() < t.cap {
		bucket.PushFront(id)
		t.len++
		return UpdateNew
	}
	return UpdateFull
}

// O(bucket_size) complexity.
func (t *Table) Delete(pub PublicKey) bool {
	bucket := t.buckets[t.bucketIndex(pub)]
	for e := bucket.Front(); e != nil; e = e.Next() {
		if e.Value.(ID).Pub == pub {
			bucket.Remove(e)
			t.len--
			return true
		}
	}
	return false
}

// Len returns the number of entries in this table.
func (t Table) Len() int {
	return t.len
}

// Has returns true if this table has pub.
func (t Table) Has(pub PublicKey) bool {
	bucket := t.buckets[t.bucketIndex(pub)]
	for e := bucket.Front(); e != nil; e = e.Next() {
		if e.Value.(ID).Pub == pub {
			return true
		}
	}
	return false
}

// O(min(k, bucket_size * num_buckets)) complexity.
func (t Table) ClosestTo(pub PublicKey, k int) []ID {
	if k > t.len {
		k = t.len
	}

	closest := make([]ID, 0, k)

	fill := func(i int) {
		for e := t.buckets[i].Front(); e != nil; e = e.Next() {
			if id := e.Value.(ID); id.Pub != pub {
				closest = append(closest, id)
			}
		}
	}

	m := t.bucketIndex(pub)

	fill(m)

	for i := 1; len(closest) < k && (m-i >= 0 || m+i < len(t.buckets)); i++ {
		if m-i >= 0 {
			fill(m - i)
		}
		if m+i < len(t.buckets) {
			fill(m + i)
		}
	}

	closest = SortIDs(t.pub, closest)

	if len(closest) > k {
		closest = closest[:k]
	}

	return closest
}
