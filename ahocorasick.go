// ahocorasick.go: implementation of the Aho-Corasick string matching
// algorithm. Actually implemented as matching against []byte rather
// than the Go string type. Throughout this code []byte is referred to
// as a blice.
//
// http://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_string_matching_algorithm
//
// Copyright (c) 2013 CloudFlare, Inc.

package ahocorasick

import (
	"container/list"
	"fmt"
)

var table = [256]byte{
	97:  0,
	98:  1,
	99:  2,
	100: 3,
	101: 4,
	102: 5,
	103: 6,
	104: 7,
	105: 8,
	106: 9,
	107: 10,
	108: 11,
	109: 12,
	110: 13,
	111: 14,
	112: 15,
	113: 16,
	114: 17,
	115: 18,
	116: 19,
	117: 20,
	118: 21,
	119: 22,
	120: 23,
	121: 24,
	122: 25,
	'-': 26,
	'.': 27,
	'^': 28,
	'$': 29,
	'1': 30,
	'2': 31,
	'3': 32,
	'4': 33,
	'5': 34,
	'6': 35,
	'7': 36,
	'8': 37,
	'9': 38,
	'0': 39,
	'_': 40,
	// Do not forget to modify the N below.
}

const N = 41

func IsValidChar(b byte) bool {
	return table[b] > 0 || b == 'a'
}

// A node in the trie structure used to implement Aho-Corasick
type node struct {
	root bool // true if this is the root

	output bool // True means this node represents a blice that should
	// be output when matching

	suffix *node // Pointer to the longest possible strict suffix of
	// this node

	fail *node // Pointer to the next node which is in the dictionary
	// which can be reached from here following suffixes. Called fail
	// because it is used to fallback in the trie when a match fails.

	b []byte // The blice at this node

	child [N]*node // A non-nil entry in this array means that the
	// index represents a byte value which can be
	// appended to the current node. Blices in the
	// trie are built up byte by byte through these
	// child node pointers.

	fails [N]*node // Where to fail to (by following the fail
	// pointers) for each possible byte
}

// Matcher is returned by NewMatcher and contains a list of blices to
// match against
type Matcher struct {
	// prevent output of multiple matches of the same string
	trie []node // preallocated block of memory containing all the
	// nodes
	extent int   // offset into trie that is currently free
	root   *node // Points to trie[0]
}

// findBlice looks for a blice in the trie starting from the root and
// returns a pointer to the node representing the end of the blice. If
// the blice is not found it returns nil.
func (m *Matcher) findBlice(b []byte) *node {
	n := &m.trie[0]

	for n != nil && len(b) > 0 {
		n = n.child[table[int(b[0])]]
		b = b[1:]
	}

	return n
}

// getFreeNode: gets a free node structure from the Matcher's trie
// pool and updates the extent to point to the next free node.
func (m *Matcher) getFreeNode() *node {
	m.extent += 1

	if m.extent == 1 {
		m.root = &m.trie[0]
		m.root.root = true
	}

	return &m.trie[m.extent-1]
}

// buildTrie builds the fundamental trie structure from a set of
// blices.
func (m *Matcher) buildTrie(dictionary [][]byte) error {

	// Work out the maximum size for the trie (all dictionary entries
	// are distinct plus the root). This is used to preallocate memory
	// for it.

	max := 1
	for _, blice := range dictionary {
		max += len(blice)
	}
	m.trie = make([]node, max)

	// Calling this an ignoring its argument simply allocated
	// m.trie[0] which will be the root element

	m.getFreeNode()

	// This loop builds the nodes in the trie by following through
	// each dictionary entry building the children pointers.

	for _, blice := range dictionary {
		n := m.root
		var path []byte
		for _, b := range blice {
			if !IsValidChar(b) {
				return fmt.Errorf("char out of range: %c", b)
			}
			path = append(path, b)

			c := n.child[table[int(b)]]

			if c == nil {
				c = m.getFreeNode()
				n.child[table[int(b)]] = c
				c.b = make([]byte, len(path))
				copy(c.b, path)

				// Nodes directly under the root node will have the
				// root as their fail point as there are no suffixes
				// possible.

				if len(path) == 1 {
					c.fail = m.root
				}

				c.suffix = m.root
			}

			n = c
		}

		// The last value of n points to the node representing a
		// dictionary entry

		n.output = true
	}

	l := new(list.List)
	l.PushBack(m.root)

	for l.Len() > 0 {
		n := l.Remove(l.Front()).(*node)

		for i := 0; i < N; i++ {
			c := n.child[i]
			if c != nil {
				l.PushBack(c)

				for j := 1; j < len(c.b); j++ {
					c.fail = m.findBlice(c.b[j:])
					if c.fail != nil {
						break
					}
				}

				if c.fail == nil {
					c.fail = m.root
				}

				for j := 1; j < len(c.b); j++ {
					s := m.findBlice(c.b[j:])
					if s != nil && s.output {
						c.suffix = s
						break
					}
				}
			}
		}
	}

	for i := 0; i < m.extent; i++ {
		for c := 0; c < N; c++ {
			n := &m.trie[i]
			for n.child[c] == nil && !n.root {
				n = n.fail
			}

			m.trie[i].fails[c] = n
		}
	}

	m.trie = m.trie[:m.extent]
	return nil
}

// NewMatcher creates a new Matcher used to match against a set of
// blices
func NewMatcher(dictionary [][]byte) (m *Matcher, err error) {
	m = new(Matcher)

	if err = m.buildTrie(dictionary); err != nil {
		return nil, err
	}

	return m, nil
}

// Contains returns true if any string matches. This can be faster
// than Match() when you do not need to know which words matched.
func (m *Matcher) Contains(in []byte) bool {
	n := m.root
	for _, b := range in {
		if !n.root {
			n = n.fails[table[b]]
		}

		if n.child[table[b]] != nil {
			f := n.child[table[b]]
			n = f

			if f.output {
				return true
			}

			for !f.suffix.root {
				return true
			}
		}
	}
	return false
}
