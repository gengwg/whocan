package main

import (
	"reflect"
	"strings"
	"testing"
)

func ptr(i int) *int { return &i }

var team = []member{
	{ID: 1, Username: "owner", AccessLevel: 50, State: "active"},
	{ID: 2, Username: "maint", AccessLevel: 40, State: "active"},
	{ID: 3, Username: "dev", AccessLevel: 30, State: "active"},
	{ID: 4, Username: "reporter", AccessLevel: 20, State: "active"},
}

func usernames(ms []member) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Username)
	}
	return out
}

func rule(name string, merge ...accessLevel) protectedBranch {
	return protectedBranch{Name: name, Merge: merge, Push: []accessLevel{{AccessLevel: 40}}}
}

var (
	maintainers = accessLevel{AccessLevel: 40, Description: "Maintainers"}
	developers  = accessLevel{AccessLevel: 30, Description: "Developers + Maintainers"}
	noOne       = accessLevel{AccessLevel: 0, Description: "No one"}
)

func TestDecide(t *testing.T) {
	tests := []struct {
		name   string
		rules  []protectedBranch
		branch string
		action string
		want   []string
	}{
		{"unprotected branch is Developer and up", nil, "feat/x", "merge", []string{"owner", "maint", "dev"}},
		{"maintainers only", []protectedBranch{rule("main", maintainers)}, "main", "merge", []string{"owner", "maint"}},
		{"no one", []protectedBranch{rule("main", noOne)}, "main", "merge", nil},
		{"push uses push levels", []protectedBranch{rule("main", developers)}, "main", "push", []string{"owner", "maint"}},
		{"rule for another branch does not apply", []protectedBranch{rule("develop", noOne)}, "main", "merge", []string{"owner", "maint", "dev"}},
		{"wildcard spans slashes", []protectedBranch{rule("release/*", noOne)}, "release/v1/hotfix", "merge", nil},
		{
			"most permissive matching rule wins",
			[]protectedBranch{rule("release/v1", maintainers), rule("release/*", developers)},
			"release/v1", "merge", []string{"owner", "maint", "dev"},
		},
		{
			"user entry grants that user only",
			[]protectedBranch{rule("main", noOne, accessLevel{AccessLevel: 40, UserID: ptr(3)})},
			"main", "merge", []string{"dev"},
		},
		{
			"deploy key grants no human",
			[]protectedBranch{{Name: "main", Push: []accessLevel{{AccessLevel: 40, DeployKeyID: ptr(9)}}}},
			"main", "push", nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := decide(tt.rules, team, tt.branch, tt.action)
			if err != nil {
				t.Fatal(err)
			}
			if got := usernames(v.Allowed); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("allowed = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecideRefusesGroupEntries(t *testing.T) {
	rules := []protectedBranch{rule("main", accessLevel{AccessLevel: 30, GroupID: ptr(7)})}
	if _, err := decide(rules, team, "main", "merge"); err == nil {
		t.Fatal("want an error for a group-scoped rule, got none")
	}
}

func TestDecideCodeOwnersFollowsMostPermissive(t *testing.T) {
	strict := rule("main", developers)
	strict.CodeOwnersRequired = true
	loose := rule("*", developers)

	v, _ := decide([]protectedBranch{strict}, team, "main", "merge")
	if !v.CodeOwners {
		t.Error("single rule requiring code owners: want CodeOwners")
	}
	v, _ = decide([]protectedBranch{strict, loose}, team, "main", "merge")
	if v.CodeOwners {
		t.Error("a matching rule without code owners is more permissive: want no CodeOwners")
	}
}

func TestEffectiveKeepsHighestActiveMembership(t *testing.T) {
	got := effective([]member{
		{ID: 2, Username: "b", AccessLevel: 30, State: "active"},
		{ID: 2, Username: "b", AccessLevel: 40, State: "active"},
		{ID: 1, Username: "a", AccessLevel: 50, State: "blocked"},
		{ID: 3, Username: "c", AccessLevel: 30, State: "awaiting"},
		{ID: 4, Username: "project_123_bot_abc", AccessLevel: 40, State: "active"},
	})
	want := []member{{ID: 2, Username: "b", AccessLevel: 40, State: "active"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("effective = %v, want %v", got, want)
	}
}

func TestDecodeAllReadsPaginatedArrays(t *testing.T) {
	got, err := decodeAll[member](strings.NewReader(`[{"id":1},{"id":2}][{"id":3}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2].ID != 3 {
		t.Errorf("decodeAll = %v, want 3 members across both pages", got)
	}
}
