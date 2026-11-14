package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
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
	return protectedBranch{Name: name, Merge: merge, Push: []accessLevel{noOne}}
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
		{
			"push uses push levels",
			[]protectedBranch{{Name: "main", Merge: []accessLevel{developers}, Push: []accessLevel{maintainers}}},
			"main", "push", []string{"owner", "maint"},
		},
		{
			"push access also grants merge",
			[]protectedBranch{{Name: "main", Merge: []accessLevel{noOne}, Push: []accessLevel{developers}}},
			"main", "merge", []string{"owner", "maint", "dev"},
		},
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
			v, err := decide(tt.rules, team, tt.branch, tt.action, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := usernames(v.Allowed); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("allowed = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDescribeNamesMostPermissive(t *testing.T) {
	bob := accessLevel{AccessLevel: 40, UserID: ptr(3), Description: "Bob"}
	key := accessLevel{AccessLevel: 40, DeployKeyID: ptr(9), Description: "ci key"}
	tests := []struct {
		entries []accessLevel
		want    string
	}{
		{[]accessLevel{maintainers, developers}, "Developers + Maintainers"},
		{[]accessLevel{developers, maintainers}, "Developers + Maintainers"},
		{[]accessLevel{noOne, maintainers}, "Maintainers"},
		{[]accessLevel{noOne}, "No one"},
		{[]accessLevel{noOne, bob}, "Bob"},
		{[]accessLevel{maintainers, bob, bob}, "Maintainers, Bob"},
		{[]accessLevel{key}, "No one"},
	}
	for _, tt := range tests {
		if got := describe(tt.entries); got != tt.want {
			t.Errorf("describe(%v) = %q, want %q", tt.entries, got, tt.want)
		}
	}
}

func TestDecideResolvesGroupEntries(t *testing.T) {
	grant := accessLevel{GroupID: ptr(7), Description: "Release Team"}
	rules := []protectedBranch{rule("main", noOne, grant)}
	groups := map[int][]member{7: {{ID: 3, Username: "dev", AccessLevel: 30, State: "active"}}}

	v, err := decide(rules, team, "main", "merge", groups)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := usernames(v.Allowed), []string{"dev"}; !reflect.DeepEqual(got, want) {
		t.Errorf("allowed = %v, want %v", got, want)
	}
	if v.Rule != "Release Team" {
		t.Errorf("rule = %q, want Release Team", v.Rule)
	}
}

func TestDecideGroupGrantRequiresActiveDeveloper(t *testing.T) {
	grant := accessLevel{GroupID: ptr(7), Description: "Release Team"}
	rules := []protectedBranch{rule("main", noOne, grant)}
	tests := []struct {
		name   string
		member member
	}{
		{"reporter in group", member{ID: 3, Username: "dev", AccessLevel: 20, State: "active"}},
		{"awaiting developer in group", member{ID: 3, Username: "dev", AccessLevel: 30, State: "awaiting"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groups := map[int][]member{7: {tt.member}}
			v, err := decide(rules, team, "main", "merge", groups)
			if err != nil {
				t.Fatal(err)
			}
			if len(v.Allowed) != 0 {
				t.Errorf("allowed = %v, want no one", usernames(v.Allowed))
			}
		})
	}
}

func TestDecideRefusesCustomRoleEntries(t *testing.T) {
	grant := accessLevel{AccessLevel: 30, MemberRoleID: ptr(42), Description: "Lead Developer"}
	rules := []protectedBranch{rule("main", grant)}
	if _, err := decide(rules, team, "main", "merge", nil); err == nil {
		t.Fatal("want an error for a custom-role rule, got none")
	}
}

func TestDecideCodeOwnersUsesMostRestrictive(t *testing.T) {
	strict := rule("main", developers)
	strict.CodeOwnersRequired = true
	loose := rule("*", developers)

	v, _ := decide([]protectedBranch{strict}, team, "main", "merge", nil)
	if !v.CodeOwners {
		t.Error("single rule requiring code owners: want CodeOwners")
	}
	v, _ = decide([]protectedBranch{strict, loose}, team, "main", "merge", nil)
	if !v.CodeOwners {
		t.Error("any matching rule requiring code owners: want CodeOwners")
	}
	v, _ = decide([]protectedBranch{loose}, team, "main", "merge", nil)
	if v.CodeOwners {
		t.Error("no matching rule requiring code owners: want no CodeOwners")
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

func fakeGlab(t *testing.T, responses map[string]string) {
	t.Helper()
	dir := t.TempDir()
	var script strings.Builder
	script.WriteString("#!/bin/sh\nif [ \"$1\" != api ]; then exit 9; fi\nshift\ncase \"$*\" in\n")
	i := 0
	for call, response := range responses {
		path := filepath.Join(dir, fmt.Sprintf("response-%d", i))
		if err := os.WriteFile(path, []byte(response), 0o600); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&script, "%q) cat %q ;;\n", call, path)
		i++
	}
	script.WriteString("*) printf 'unexpected glab call: %s\\n' \"$*\" >&2; exit 9 ;;\nesac\n")
	if err := os.WriteFile(filepath.Join(dir, "glab"), []byte(script.String()), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func runResponses(rules, me string) map[string]string {
	return map[string]string{
		"projects/acme%2Fdemo": `{"id":42,"path_with_namespace":"acme/demo","default_branch":"main"}`,
		"--paginate projects/42/protected_branches?per_page=100": `[` + rules + `]`,
		"--paginate projects/42/members/all?per_page=100": `[
			{"id":3,"username":"dev","access_level":30,"state":"active"}
		][
			{"id":5,"username":"grouped","access_level":30,"state":"active"},
			{"id":6,"username":"inherited","access_level":40,"state":"active"}
		]`,
		"user": me,
	}
}

func TestRunResolvesDirectGroupMembers(t *testing.T) {
	rules := `{
		"name":"main",
		"merge_access_levels":[{"access_level":0,"access_level_description":"No one"}],
		"push_access_levels":[{"access_level":null,"group_id":7,"access_level_description":"Release Team"}],
		"code_owner_approval_required":true
	}`
	tests := []struct {
		name    string
		me      string
		wantCan bool
		wantYou string
	}{
		{
			name:    "direct group member can merge through push grant",
			me:      `{"id":5,"username":"grouped"}`,
			wantCan: true,
			wantYou: "you: grouped (Developer), can\n",
		},
		{
			name:    "other project member cannot",
			me:      `{"id":3,"username":"dev"}`,
			wantCan: false,
			wantYou: "you: dev (Developer), cannot\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			responses := runResponses(rules, tt.me)
			responses["--paginate groups/7/members?per_page=100"] = `[
				{"id":5,"username":"grouped","access_level":30,"state":"active"}
			]`
			fakeGlab(t, responses)

			var out bytes.Buffer
			can, err := run([]string{"acme/demo", "main", "merge"}, &out)
			if err != nil {
				t.Fatal(err)
			}
			if can != tt.wantCan {
				t.Errorf("can = %v, want %v", can, tt.wantCan)
			}
			want := "acme/demo main merge: protected (Release Team)\n" + tt.wantYou +
				"can: grouped (Developer)\n" +
				"note: code-owner approval is also required for owned paths; see CODEOWNERS\n"
			if out.String() != want {
				t.Errorf("output:\n%s\nwant:\n%s", out.String(), want)
			}
		})
	}
}

func TestRunOmitsCodeOwnersNoteForAllowedPush(t *testing.T) {
	rules := `{
		"name":"main",
		"merge_access_levels":[{"access_level":0,"access_level_description":"No one"}],
		"push_access_levels":[{"access_level":30,"access_level_description":"Developers + Maintainers"}],
		"code_owner_approval_required":true
	}`
	fakeGlab(t, runResponses(rules, `{"id":3,"username":"dev"}`))

	var out bytes.Buffer
	can, err := run([]string{"acme/demo", "main", "push"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !can {
		t.Error("can = false, want true")
	}
	if strings.Contains(out.String(), "CODEOWNERS") {
		t.Errorf("output contains a misleading Code Owner push note: %q", out.String())
	}
}

func TestRunRefusesCustomRole(t *testing.T) {
	rules := `{
		"name":"main",
		"merge_access_levels":[{
			"access_level":30,
			"member_role_id":42,
			"access_level_description":"Lead Developer"
		}],
		"push_access_levels":[{"access_level":0,"access_level_description":"No one"}]
	}`
	fakeGlab(t, runResponses(rules, `{"id":3,"username":"dev"}`))

	var out bytes.Buffer
	can, err := run([]string{"acme/demo", "main", "merge"}, &out)
	if err == nil || !strings.Contains(err.Error(), "custom role") {
		t.Fatalf("error = %v, want a custom-role error", err)
	}
	if can {
		t.Error("can = true, want false")
	}
	if out.Len() != 0 {
		t.Errorf("output = %q, want none", out.String())
	}
}
