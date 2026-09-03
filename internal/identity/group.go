package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/storage"
)

// ErrGroupNotFound is returned when a group ID or name has no record.
var ErrGroupNotFound = errors.New("identity: group not found")

// Group is an internal collection of entities (and, nested, other groups) with
// its own policies. An entity that is a transitive member of a group picks up
// the group's policies, on top of its own. External groups (membership asserted
// by an auth method) are a later phase; every group here is internal.
type Group struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Policies        []string          `json:"policies,omitempty"`
	MemberEntityIDs []string          `json:"member_entity_ids,omitempty"`
	MemberGroupIDs  []string          `json:"member_group_ids,omitempty"` // child groups; their members inherit this group's policies
	Metadata        map[string]string `json:"metadata,omitempty"`
	CreatedTime     time.Time         `json:"created_time"`
}

func (e *Engine) groupKey(id string) string    { return e.prefix + "/group/" + id }
func (e *Engine) groupNameKey(n string) string { return e.prefix + "/group-name/" + n }

// WriteGroup creates or updates the group named name (upsert by name),
// replacing its policies, members, and metadata.
func (e *Engine) WriteGroup(ctx context.Context, name string, policies, memberEntityIDs, memberGroupIDs []string, metadata map[string]string) (*Group, error) {
	if !validName(name) {
		return nil, ErrInvalidName
	}
	existing, err := e.ReadGroupByName(ctx, name)
	switch {
	case errors.Is(err, ErrGroupNotFound):
		id, err := genID()
		if err != nil {
			return nil, err
		}
		g := &Group{ID: id, Name: name, CreatedTime: e.now()}
		return e.saveGroup(ctx, g, policies, memberEntityIDs, memberGroupIDs, metadata)
	case err != nil:
		return nil, err
	default:
		return e.saveGroup(ctx, existing, policies, memberEntityIDs, memberGroupIDs, metadata)
	}
}

// UpdateGroup replaces the policies, members, and metadata of the group
// addressed by ID, leaving its name unchanged. Returns [ErrGroupNotFound] if the
// ID is unknown.
func (e *Engine) UpdateGroup(ctx context.Context, id string, policies, memberEntityIDs, memberGroupIDs []string, metadata map[string]string) (*Group, error) {
	g, err := e.ReadGroup(ctx, id)
	if err != nil {
		return nil, err
	}
	return e.saveGroup(ctx, g, policies, memberEntityIDs, memberGroupIDs, metadata)
}

func (e *Engine) saveGroup(ctx context.Context, g *Group, policies, memberEntityIDs, memberGroupIDs []string, metadata map[string]string) (*Group, error) {
	g.Policies = policies
	g.MemberEntityIDs = memberEntityIDs
	g.MemberGroupIDs = memberGroupIDs
	g.Metadata = metadata
	blob, err := json.Marshal(g)
	if err != nil {
		return nil, fmt.Errorf("identity: marshal group: %w", err)
	}
	if err := e.store.Put(ctx, &storage.Entry{Key: e.groupKey(g.ID), Value: blob}); err != nil {
		return nil, fmt.Errorf("identity: persist group: %w", err)
	}
	if err := e.store.Put(ctx, &storage.Entry{Key: e.groupNameKey(g.Name), Value: []byte(g.ID)}); err != nil {
		return nil, fmt.Errorf("identity: persist group name index: %w", err)
	}
	return g, nil
}

// ReadGroup returns the group with the given ID, or [ErrGroupNotFound].
func (e *Engine) ReadGroup(ctx context.Context, id string) (*Group, error) {
	entry, err := e.store.Get(ctx, e.groupKey(id))
	if err != nil {
		return nil, fmt.Errorf("identity: read group: %w", err)
	}
	if entry == nil {
		return nil, ErrGroupNotFound
	}
	var g Group
	if err := json.Unmarshal(entry.Value, &g); err != nil {
		return nil, fmt.Errorf("identity: unmarshal group: %w", err)
	}
	return &g, nil
}

// ReadGroupByName returns the group with the given name, or [ErrGroupNotFound].
func (e *Engine) ReadGroupByName(ctx context.Context, name string) (*Group, error) {
	entry, err := e.store.Get(ctx, e.groupNameKey(name))
	if err != nil {
		return nil, fmt.Errorf("identity: read group name index: %w", err)
	}
	if entry == nil {
		return nil, ErrGroupNotFound
	}
	return e.ReadGroup(ctx, string(entry.Value))
}

// ListGroups returns all group IDs.
func (e *Engine) ListGroups(ctx context.Context) ([]string, error) {
	ids, err := e.store.List(ctx, e.prefix+"/group/")
	if err != nil {
		return nil, fmt.Errorf("identity: list groups: %w", err)
	}
	return ids, nil
}

// DeleteGroup removes a group and its name index. It is a no-op if absent.
// References to the deleted group in other groups' MemberGroupIDs simply stop
// resolving; they are harmless.
func (e *Engine) DeleteGroup(ctx context.Context, id string) error {
	g, err := e.ReadGroup(ctx, id)
	if errors.Is(err, ErrGroupNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := e.store.Delete(ctx, e.groupNameKey(g.Name)); err != nil {
		return fmt.Errorf("identity: delete group name index: %w", err)
	}
	if err := e.store.Delete(ctx, e.groupKey(id)); err != nil {
		return fmt.Errorf("identity: delete group: %w", err)
	}
	return nil
}

// groupPoliciesForEntity returns the policies of every group the entity is a
// transitive member of: groups that list it directly, plus every ancestor group
// that lists one of those groups as a child (to any depth). It loads all groups
// and computes the closure by fixpoint, which tolerates cycles in
// MemberGroupIDs.
func (e *Engine) groupPoliciesForEntity(ctx context.Context, entityID string) ([]string, error) {
	ids, err := e.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	groups := make([]*Group, 0, len(ids))
	for _, id := range ids {
		g, err := e.ReadGroup(ctx, id)
		if errors.Is(err, ErrGroupNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}

	// Seed: groups that list the entity directly.
	applicable := make(map[string]bool)
	for _, g := range groups {
		if contains(g.MemberEntityIDs, entityID) {
			applicable[g.ID] = true
		}
	}
	// Fixpoint: a group applies if it lists an already-applicable group as a child.
	for changed := true; changed; {
		changed = false
		for _, g := range groups {
			if applicable[g.ID] {
				continue
			}
			for _, child := range g.MemberGroupIDs {
				if applicable[child] {
					applicable[g.ID] = true
					changed = true
					break
				}
			}
		}
	}

	var policies []string
	for _, g := range groups {
		if applicable[g.ID] {
			policies = append(policies, g.Policies...)
		}
	}
	return policies, nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
