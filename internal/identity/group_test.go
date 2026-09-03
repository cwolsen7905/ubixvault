package identity

import (
	"context"
	"errors"
	"sort"
	"testing"
)

func TestWriteReadGroup(t *testing.T) {
	ctx := context.Background()
	e := newEngine()
	g, err := e.WriteGroup(ctx, "platform", []string{"p-admin"}, []string{"e1", "e2"}, nil, nil)
	if err != nil {
		t.Fatalf("WriteGroup: %v", err)
	}
	got, err := e.ReadGroup(ctx, g.ID)
	if err != nil || got.Name != "platform" || len(got.MemberEntityIDs) != 2 {
		t.Fatalf("ReadGroup = %+v, %v", got, err)
	}
	byName, err := e.ReadGroupByName(ctx, "platform")
	if err != nil || byName.ID != g.ID {
		t.Fatalf("ReadGroupByName = %+v, %v", byName, err)
	}
}

func TestWriteGroupUpsertsByName(t *testing.T) {
	ctx := context.Background()
	e := newEngine()
	first, _ := e.WriteGroup(ctx, "g", []string{"a"}, nil, nil, nil)
	second, err := e.WriteGroup(ctx, "g", []string{"b"}, nil, nil, nil)
	if err != nil {
		t.Fatalf("second WriteGroup: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("upsert changed ID: %s -> %s", first.ID, second.ID)
	}
}

// TestGroupPolicyInPoliciesFor is the core Phase-2 behavior: an entity that is a
// member of a group picks up the group's policies through PoliciesFor.
func TestGroupPolicyInPoliciesFor(t *testing.T) {
	ctx := context.Background()
	e := newEngine()
	ent, _ := e.WriteEntity(ctx, "alice", []string{"own"}, nil, false)
	if _, err := e.WriteGroup(ctx, "platform", []string{"grp"}, []string{ent.ID}, nil, nil); err != nil {
		t.Fatalf("WriteGroup: %v", err)
	}

	got, err := e.PoliciesFor(ctx, ent.ID)
	if err != nil {
		t.Fatalf("PoliciesFor: %v", err)
	}
	sort.Strings(got)
	if len(got) != 2 || got[0] != "grp" || got[1] != "own" {
		t.Fatalf("PoliciesFor = %v, want [grp own]", got)
	}

	// A non-member entity does not get the group policy.
	other, _ := e.WriteEntity(ctx, "bob", []string{"own2"}, nil, false)
	og, _ := e.PoliciesFor(ctx, other.ID)
	if len(og) != 1 || og[0] != "own2" {
		t.Fatalf("non-member PoliciesFor = %v, want [own2]", og)
	}
}

// TestNestedGroupPolicies covers transitive membership: a member of a child
// group inherits the parent group's policies too, and a cycle does not hang.
func TestNestedGroupPolicies(t *testing.T) {
	ctx := context.Background()
	e := newEngine()
	ent, _ := e.WriteEntity(ctx, "carol", nil, nil, false)

	child, _ := e.WriteGroup(ctx, "child", []string{"child-pol"}, []string{ent.ID}, nil, nil)
	parent, _ := e.WriteGroup(ctx, "parent", []string{"parent-pol"}, nil, []string{child.ID}, nil)
	// Introduce a cycle: child also lists parent as a child.
	if _, err := e.WriteGroup(ctx, "child", []string{"child-pol"}, []string{ent.ID}, []string{parent.ID}, nil); err != nil {
		t.Fatalf("rewrite child: %v", err)
	}

	got, err := e.PoliciesFor(ctx, ent.ID)
	if err != nil {
		t.Fatalf("PoliciesFor: %v", err)
	}
	sort.Strings(got)
	if len(got) != 2 || got[0] != "child-pol" || got[1] != "parent-pol" {
		t.Fatalf("PoliciesFor = %v, want [child-pol parent-pol]", got)
	}
}

func TestDeleteGroup(t *testing.T) {
	ctx := context.Background()
	e := newEngine()
	ent, _ := e.WriteEntity(ctx, "dave", nil, nil, false)
	g, _ := e.WriteGroup(ctx, "temp", []string{"gp"}, []string{ent.ID}, nil, nil)

	if err := e.DeleteGroup(ctx, g.ID); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	if _, err := e.ReadGroup(ctx, g.ID); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("group survived delete: %v", err)
	}
	// The entity no longer inherits the deleted group's policy.
	if got, _ := e.PoliciesFor(ctx, ent.ID); len(got) != 0 {
		t.Fatalf("PoliciesFor after group delete = %v, want empty", got)
	}
}

func TestReadGroupMissing(t *testing.T) {
	if _, err := newEngine().ReadGroup(context.Background(), "nope"); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("ReadGroup missing = %v, want ErrGroupNotFound", err)
	}
}
