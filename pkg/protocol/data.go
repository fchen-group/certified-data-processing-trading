// Package protocol contains the shared, versioned wire and cryptographic rules.
package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/bits"
	"sort"
)

type Hash [32]byte

func (h Hash) MarshalJSON() ([]byte, error) { return json.Marshal("0x" + hex.EncodeToString(h[:])) }
func (h *Hash) UnmarshalJSON(b []byte) error {
	var s string
	if e := json.Unmarshal(b, &s); e != nil {
		return e
	}
	if len(s) != 66 || s[:2] != "0x" {
		return errors.New("hash must have 32 hex bytes")
	}
	raw, e := hex.DecodeString(s[2:])
	if e != nil {
		return e
	}
	copy(h[:], raw)
	return nil
}
func H(b []byte) Hash { return sha256.Sum256(b) }

// Encode uses a uint64 big-endian length for EVERY field, including integers.
func Encode(fields ...[]byte) []byte {
	var b bytes.Buffer
	for _, f := range fields {
		b.Write(U64(uint64(len(f))))
		b.Write(f)
	}
	return b.Bytes()
}
func U64(n uint64) []byte          { b := make([]byte, 8); binary.BigEndian.PutUint64(b, n); return b }
func JSONHash(v any) (Hash, error) { b, e := json.Marshal(v); return H(b), e }

type Dataset struct {
	Records [][]byte `json:"records"`
	Salts   []Hash   `json:"salts"`
}

func Prepare(records [][]byte) (Dataset, error) {
	if len(records) == 0 {
		return Dataset{}, errors.New("empty records")
	}
	d := Dataset{Records: make([][]byte, len(records)), Salts: make([]Hash, len(records))}
	for i, r := range records {
		d.Records[i] = bytes.Clone(r)
		if _, e := rand.Read(d.Salts[i][:]); e != nil {
			return Dataset{}, e
		}
	}
	return d, nil
}
func (d Dataset) Validate() error {
	if len(d.Records) == 0 || len(d.Records) != len(d.Salts) {
		return errors.New("empty records or salt count mismatch")
	}
	return nil
}

type node struct {
	hash        Hash
	count       int
	left, right *node
}
type Tree struct{ root *node }

func leaf(index uint64, r []byte, s Hash) Hash {
	return H(append([]byte{0}, Encode(U64(index), r, s[:])...))
}
func branch(l, r Hash) Hash           { b := append([]byte{1}, l[:]...); b = append(b, r[:]...); return H(b) }
func Commit(n uint64, root Hash) Hash { return H(append([]byte{2}, Encode(U64(n), root[:])...)) }
func split(n int) int                 { return 1 << (bits.Len(uint(n-1)) - 1) }
func Build(d Dataset) (*Tree, error) {
	if e := d.Validate(); e != nil {
		return nil, e
	}
	var build func(int, int) *node
	build = func(start, n int) *node {
		if n == 1 {
			return &node{hash: leaf(uint64(start+1), d.Records[start], d.Salts[start]), count: 1}
		}
		k := split(n)
		l, r := build(start, k), build(start+k, n-k)
		return &node{hash: branch(l.hash, r.hash), count: n, left: l, right: r}
	}
	return &Tree{root: build(0, len(d.Records))}, nil
}
func (t *Tree) Commitment() Hash { return Commit(uint64(t.root.count), t.root.hash) }

// ReconstructCommitment needs no retained proof tree. The complete input is
// still held in memory; this does not impose a streaming analysis interface.
func ReconstructCommitment(d Dataset) (Hash, error) {
	if e := d.Validate(); e != nil {
		return Hash{}, e
	}
	var root func(int, int) Hash
	root = func(start, n int) Hash {
		if n == 1 {
			return leaf(uint64(start+1), d.Records[start], d.Salts[start])
		}
		k := split(n)
		return branch(root(start, k), root(start+k, n-k))
	}
	return Commit(uint64(len(d.Records)), root(0, len(d.Records))), nil
}

type Proof struct {
	Siblings []Hash `json:"siblings"`
}

// Siblings are ordered from leaf to root; directions follow index and tree size.
func (t *Tree) Proof(index uint64) (Proof, error) {
	if index == 0 || index > uint64(t.root.count) {
		return Proof{}, errors.New("index out of range")
	}
	p := Proof{}
	var walk func(*node, int)
	walk = func(n *node, i int) {
		if n.count == 1 {
			return
		}
		k := n.left.count
		if i < k {
			walk(n.left, i)
			p.Siblings = append(p.Siblings, n.right.hash)
		} else {
			walk(n.right, i-k)
			p.Siblings = append(p.Siblings, n.left.hash)
		}
	}
	walk(t.root, int(index-1))
	return p, nil
}
func Verify(commitment Hash, n, index uint64, record []byte, salt Hash, p Proof) bool {
	if n == 0 || index == 0 || index > n || len(p.Siblings) > 64 {
		return false
	}
	pos := 0
	var walk func(uint64, uint64) (Hash, bool)
	walk = func(size, i uint64) (Hash, bool) {
		if size == 1 {
			return leaf(index, record, salt), true
		}
		k := uint64(1) << (bits.Len64(size-1) - 1)
		var h Hash
		var ok bool
		if i < k {
			h, ok = walk(k, i)
		} else {
			h, ok = walk(size-k, i-k)
		}
		if !ok || pos >= len(p.Siblings) {
			return Hash{}, false
		}
		sibling := p.Siblings[pos]
		pos++
		if i < k {
			return branch(h, sibling), true
		}
		return branch(sibling, h), true
	}
	root, ok := walk(n, index-1)
	return ok && pos == len(p.Siblings) && Commit(n, root) == commitment
}

type Policy struct {
	Rho              float64 `json:"rho"`
	Epsilon          float64 `json:"epsilon"`
	MaxChallenges    uint64  `json:"max_challenges"`
	MaterialDeadline uint64  `json:"material_deadline"`
	AuditDeadline    uint64  `json:"audit_deadline"`
	BusinessRules    string  `json:"business_rules"`
}

func (p Policy) Validate() error {
	if !(p.Rho > 0 && p.Rho < 1 && p.Epsilon > 0 && p.Epsilon < 1) || p.MaxChallenges == 0 || p.MaterialDeadline == 0 || p.AuditDeadline <= p.MaterialDeadline {
		return errors.New("invalid audit policy")
	}
	return nil
}
func SampleSize(n uint64, rho, epsilon float64) (uint64, error) {
	if n == 0 || !(rho > 0 && rho < 1 && epsilon > 0 && epsilon < 1) {
		return 0, errors.New("invalid sampling arguments")
	}
	x := math.Ceil(math.Log(epsilon) / math.Log1p(-rho))
	if math.IsInf(x, 1) || x >= float64(n) {
		return n, nil
	}
	m := uint64(x)
	if m == 0 {
		m = 1
	}
	// Guard against floating-point rounding down at an integer boundary.
	for m < n && float64(m)*math.Log1p(-rho) > math.Log(epsilon) {
		m++
	}
	return m, nil
}

// Sample uses Floyd's algorithm, crypto/rand rejection sampling, and O(m) memory.
func Sample(n, m uint64, rng io.Reader) ([]uint64, error) {
	if n == 0 || m == 0 || m > n || m > uint64(int(^uint(0)>>1)) {
		return nil, errors.New("invalid sample size")
	}
	if rng == nil {
		rng = rand.Reader
	}
	selected := make(map[uint64]bool, int(m))
	for j := n - m; j < n; j++ {
		limit := new(big.Int).SetUint64(j)
		limit.Add(limit, big.NewInt(1))
		x, e := rand.Int(rng, limit)
		if e != nil {
			return nil, e
		}
		v := x.Uint64()
		if selected[v] {
			selected[j] = true
		} else {
			selected[v] = true
		}
	}
	result := make([]uint64, 0, int(m))
	for i := range selected {
		result = append(result, i+1)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}
func ChallengeHash(indices []uint64) (Hash, error) {
	if len(indices) == 0 {
		return Hash{}, errors.New("empty challenge")
	}
	var b bytes.Buffer
	b.WriteString("WORK2_CHALLENGE_V1")
	b.Write(U64(uint64(len(indices))))
	var last uint64
	for _, i := range indices {
		if i <= last {
			return Hash{}, errors.New("challenge must be sorted and unique")
		}
		b.Write(U64(i))
		last = i
	}
	return H(b.Bytes()), nil
}

type SampleRecord struct {
	Index  uint64 `json:"index"`
	Record []byte `json:"record"`
	Salt   Hash   `json:"salt"`
	Proof  Proof  `json:"proof"`
}

// Snapshot owns an immutable copy of one dataset and its proof tree. Retaining
// it lets the DO answer new challenges without rebuilding the tree. Neither
// caller-owned input buffers nor returned samples alias the retained records.
type Snapshot struct {
	data Dataset
	tree *Tree
}

func NewSnapshot(d Dataset) (*Snapshot, error) {
	if e := d.Validate(); e != nil {
		return nil, e
	}
	owned := Dataset{Records: make([][]byte, len(d.Records)), Salts: append([]Hash(nil), d.Salts...)}
	for i, r := range d.Records {
		owned.Records[i] = bytes.Clone(r)
	}
	tree, e := Build(owned)
	if e != nil {
		return nil, e
	}
	return &Snapshot{data: owned, tree: tree}, nil
}

func (s *Snapshot) Count() uint64 {
	if s == nil || s.tree == nil {
		return 0
	}
	return uint64(len(s.data.Records))
}

func (s *Snapshot) Commitment() Hash {
	if s.Count() == 0 {
		return Hash{}
	}
	return s.tree.Commitment()
}

func Respond(d Dataset, indices []uint64) ([]SampleRecord, error) {
	snapshot, e := NewSnapshot(d)
	if e != nil {
		return nil, e
	}
	return snapshot.Respond(indices)
}

func (s *Snapshot) Respond(indices []uint64) ([]SampleRecord, error) {
	if s.Count() == 0 {
		return nil, errors.New("empty snapshot")
	}
	if _, e := ChallengeHash(indices); e != nil {
		return nil, e
	}
	result := make([]SampleRecord, len(indices))
	for j, i := range indices {
		p, e := s.tree.Proof(i)
		if e != nil {
			return nil, e
		}
		result[j] = SampleRecord{i, bytes.Clone(s.data.Records[i-1]), s.data.Salts[i-1], p}
	}
	return result, nil
}
func VerifySamples(commitment Hash, n uint64, indices []uint64, samples []SampleRecord) error {
	if _, e := ChallengeHash(indices); e != nil {
		return e
	}
	if len(indices) != len(samples) {
		return errors.New("missing samples")
	}
	for j, i := range indices {
		r := samples[j]
		if i != r.Index || !Verify(commitment, n, i, r.Record, r.Salt, r.Proof) {
			return fmt.Errorf("invalid sample at index %d", i)
		}
	}
	return nil
}

// StrictJSON rejects unknown fields, trailing values and truncated documents.
func StrictJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
