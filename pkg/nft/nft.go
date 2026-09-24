/*
Copyright YEAR The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package nft replaces the ruleset of an nftables table atomically without
// recreating the table. Deleting a table deletes its base chains and
// flowtables, and unregistering a netfilter hook makes the kernel drop every
// packet waiting for a verdict in any nfqueue of the network namespace.
// https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement
package nft

import (
	"github.com/google/nftables"
)

// Table is an nftables table whose ruleset is replaced on every sync.
type Table struct {
	*nftables.Table
	recreated bool
}

// NewTable returns a Table for the given name and family.
func NewTable(name string, family nftables.TableFamily) *Table {
	return &Table{Table: &nftables.Table{Name: name, Family: family}}
}

// Begin adds to the transaction the table, if it does not exist, and the
// removal of all the rules of all its chains, and returns the table for the
// chains, sets and rules to reference. Chains, sets and flowtables are kept,
// adding them again in the same transaction is a no-op. Until the first Commit
// the table is also deleted and created again, so anything left by a previous
// version, such as a base chain with a different priority that can not be
// updated in place, is removed.
func (t *Table) Begin(tx *nftables.Conn) *nftables.Table {
	tx.AddTable(t.Table)
	tx.FlushTable(t.Table)
	if !t.recreated {
		tx.DelTable(t.Table)
		tx.AddTable(t.Table)
	}
	return t.Table
}

// Commit sends the transaction to the kernel.
func (t *Table) Commit(tx *nftables.Conn) error {
	if err := tx.Flush(); err != nil {
		return err
	}
	t.recreated = true
	return nil
}

// ReplaceSet adds to the transaction the recreation of the set with the given
// elements, Begin does not touch the sets. The rules that reference the set
// must be flushed earlier in the transaction for the delete to succeed.
func ReplaceSet(tx *nftables.Conn, set *nftables.Set, elements []nftables.SetElement) error {
	// add + delete so the delete succeeds whether or not the set exists
	if err := tx.AddSet(set, nil); err != nil {
		return err
	}
	tx.DelSet(set)
	return tx.AddSet(set, elements)
}
