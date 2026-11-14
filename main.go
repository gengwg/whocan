// whocan reports who may merge into (or push to) a GitLab branch, from live
// API data, so a plan learns about a permission wall before it reaches it.
//
//	whocan [group/project] [branch] [merge|push]
//
// The project defaults to the current directory's repo. The branch defaults to
// develop if the project has one, else the project's default branch; the action
// defaults to merge.
// Exit 0 when you can, 1 when you cannot, 2 on error. Needs an authenticated
// glab.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strings"
)

type accessLevel struct {
	AccessLevel  int    `json:"access_level"`
	Description  string `json:"access_level_description"`
	UserID       *int   `json:"user_id"`
	GroupID      *int   `json:"group_id"`
	MemberRoleID *int   `json:"member_role_id"`
	DeployKeyID  *int   `json:"deploy_key_id"`
}

type protectedBranch struct {
	Name               string        `json:"name"`
	Push               []accessLevel `json:"push_access_levels"`
	Merge              []accessLevel `json:"merge_access_levels"`
	CodeOwnersRequired bool          `json:"code_owner_approval_required"`
}

type namespace struct {
	ID   int    `json:"id"`
	Kind string `json:"kind"`
}

type projectInfo struct {
	ID            int       `json:"id"`
	Path          string    `json:"path_with_namespace"`
	DefaultBranch string    `json:"default_branch"`
	EmptyRepo     bool      `json:"empty_repo"`
	Namespace     namespace `json:"namespace"`
}

type defaultBranchProtection struct {
	AllowedToPush           []accessLevel `json:"allowed_to_push"`
	DeveloperCanInitialPush bool          `json:"developer_can_initial_push"`
}

type member struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	AccessLevel int    `json:"access_level"`
	State       string `json:"state"`
	IsAdmin     bool   `json:"is_admin"`
}

type verdict struct {
	Rule           string // "" when the branch is unprotected
	Allowed        []member
	CodeOwners     bool
	Administrators bool
}

const (
	developer     = 30
	administrator = 60
)

var roles = map[int]string{10: "Guest", 15: "Planner", 20: "Reporter", 30: "Developer", 40: "Maintainer", 50: "Owner"}

// GitLab's only wildcard is `*`, and it spans `/` (`production/*`).
func matches(pattern, branch string) bool {
	re := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
	return regexp.MustCompile(re).MatchString(branch)
}

func permits(e accessLevel, m member, groups map[int][]member) bool {
	switch {
	case e.DeployKeyID != nil, e.MemberRoleID != nil:
		return false
	case e.UserID != nil:
		return *e.UserID == m.ID
	case e.GroupID != nil:
		return slices.ContainsFunc(groups[*e.GroupID], func(g member) bool {
			return g.ID == m.ID && g.State == "active" && g.AccessLevel >= developer
		})
	case e.AccessLevel == administrator:
		return m.IsAdmin
	case e.AccessLevel == 0: // "No one"
		return false
	}
	return m.AccessLevel >= e.AccessLevel
}

// describe names what actually grants access: the most permissive role level
// plus any named users or groups. Deploy keys grant no person.
func describe(entries []accessLevel) string {
	var role *accessLevel
	var named []string
	for _, e := range entries {
		switch {
		case e.DeployKeyID != nil:
		case e.UserID != nil, e.GroupID != nil:
			if !slices.Contains(named, e.Description) {
				named = append(named, e.Description)
			}
		case role == nil || (e.AccessLevel != 0 && (role.AccessLevel == 0 || e.AccessLevel < role.AccessLevel)):
			role = &e
		}
	}
	if role == nil || (role.AccessLevel == 0 && len(named) > 0) {
		if len(named) == 0 {
			return "No one"
		}
		return strings.Join(named, ", ")
	}
	return strings.Join(append([]string{role.Description}, named...), ", ")
}

func accessEntries(r protectedBranch, action string) []accessLevel {
	if action == "merge" {
		// GitLab's "Allowed to push and merge" grants both capabilities.
		return slices.Concat(r.Merge, r.Push)
	}
	return r.Push
}

// decide applies GitLab's rule: when several protected-branch rules match,
// the most permissive one controls the branch, so the allowed set is the union.
func decide(rules []protectedBranch, members []member, branch, action string, groups map[int][]member) (verdict, error) {
	var matched []protectedBranch
	for _, r := range rules {
		if matches(r.Name, branch) {
			matched = append(matched, r)
		}
	}

	var v verdict
	var entries []accessLevel
	if len(matched) == 0 {
		entries = []accessLevel{{AccessLevel: developer}}
	} else {
		for _, r := range matched {
			// Unlike access rules, Code Owner approval uses the most restrictive match.
			v.CodeOwners = v.CodeOwners || r.CodeOwnersRequired
			for _, e := range accessEntries(r, action) {
				if e.MemberRoleID != nil {
					return v, fmt.Errorf("rule %q grants %s to a custom role, which whocan does not resolve", r.Name, action)
				}
				v.Administrators = v.Administrators || e.AccessLevel == administrator
				entries = append(entries, e)
			}
		}
		v.Rule = describe(entries)
	}

	for _, m := range members {
		for _, e := range entries {
			if permits(e, m, groups) {
				v.Allowed = append(v.Allowed, m)
				break
			}
		}
	}
	return v, nil
}

// Project and group access tokens appear as members named like this; they are
// not people anyone can hand a merge to.
var tokenBot = regexp.MustCompile(`^(project|group)_\d+_bot_`)

// effective keeps active human members only, at their highest access level:
// members/all can list one user once per membership source.
func effective(all []member) []member {
	best := map[int]member{}
	for _, m := range all {
		if m.State != "active" || tokenBot.MatchString(m.Username) {
			continue
		}
		if b, ok := best[m.ID]; !ok || m.AccessLevel > b.AccessLevel {
			best[m.ID] = m
		}
	}
	out := make([]member, 0, len(best))
	for _, m := range best {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// candidates marks the current administrator only on real project memberships.
// A nonmember admin's level-60 verdict is handled separately in run.
func candidates(members []member, me member) []member {
	activeAdmin := me.IsAdmin && me.State == "active"
	for i := range members {
		if members[i].ID == me.ID {
			members[i].IsAdmin = activeAdmin
		}
	}
	return members
}

// decodeAll reads one or more concatenated JSON arrays, which is what
// `glab api --paginate` prints.
func decodeAll[T any](r io.Reader) ([]T, error) {
	var out []T
	dec := json.NewDecoder(r)
	for {
		var page []T
		if err := dec.Decode(&page); errors.Is(err, io.EOF) {
			return out, nil
		} else if err != nil {
			return nil, err
		}
		out = append(out, page...)
	}
}

func glab(args ...string) ([]byte, error) {
	var stderr bytes.Buffer
	cmd := exec.Command("glab", append([]string{"api"}, args...)...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("glab api %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func glabList[T any](endpoint string) ([]T, error) {
	out, err := glab("--paginate", endpoint+"?per_page=100")
	if err != nil {
		return nil, err
	}
	return decodeAll[T](bytes.NewReader(out))
}

func glabGroupMembers(rules []protectedBranch, branch, action string) (map[int][]member, error) {
	groups := map[int][]member{}
	for _, r := range rules {
		if !matches(r.Name, branch) {
			continue
		}
		for _, e := range accessEntries(r, action) {
			if e.GroupID == nil {
				continue
			}
			id := *e.GroupID
			if _, loaded := groups[id]; loaded {
				continue
			}
			// Protected-branch group grants include direct group members only.
			members, err := glabList[member](fmt.Sprintf("groups/%d/members", id))
			if err != nil {
				return nil, err
			}
			groups[id] = members
		}
	}
	return groups, nil
}

func glabGet(endpoint string, v any) error {
	out, err := glab(endpoint)
	if err != nil {
		return err
	}
	return json.Unmarshal(out, v)
}

func developerInitialPush(legacy *int, defaults *defaultBranchProtection) (bool, error) {
	if defaults != nil {
		if defaults.DeveloperCanInitialPush {
			return true, nil
		}
		return slices.ContainsFunc(defaults.AllowedToPush, func(e accessLevel) bool {
			return e.AccessLevel == developer
		}), nil
	}
	if legacy != nil {
		switch *legacy {
		case 0, 1, 4:
			return true, nil
		case 2, 3:
			return false, nil
		}
	}
	return false, errors.New("initial default-branch protection is unavailable")
}

func glabInitialPushAccess(ns namespace) ([]accessLevel, error) {
	if ns.Kind == "user" {
		return nil, errors.New("cannot determine initial branch protection for a personal namespace")
	}
	if ns.Kind != "group" {
		return nil, fmt.Errorf("cannot determine initial branch protection for namespace kind %q", ns.Kind)
	}
	var group struct {
		Legacy   *int                     `json:"default_branch_protection"`
		Defaults *defaultBranchProtection `json:"default_branch_protection_defaults"`
	}
	if err := glabGet(fmt.Sprintf("groups/%d?with_projects=false", ns.ID), &group); err != nil {
		return nil, err
	}
	developerCan, err := developerInitialPush(group.Legacy, group.Defaults)
	if err != nil {
		return nil, err
	}
	entry := accessLevel{AccessLevel: 40, Description: "Maintainers"}
	if developerCan {
		entry = accessLevel{AccessLevel: developer, Description: "Developers + Maintainers"}
	}
	return []accessLevel{entry}, nil
}

func run(args []string, out io.Writer) (bool, error) {
	if len(args) > 3 {
		return false, errors.New("usage: whocan [group/project] [branch] [merge|push]")
	}
	// glab resolves :fullpath from the current directory's git remote.
	project := ":fullpath"
	if len(args) > 0 {
		project = url.PathEscape(args[0])
	}
	action := "merge"
	if len(args) == 3 {
		action = args[2]
	}
	if action != "merge" && action != "push" {
		return false, fmt.Errorf("action must be merge or push, got %q", action)
	}

	var proj projectInfo
	if err := glabGet("projects/"+project, &proj); err != nil {
		if len(args) == 0 && strings.Contains(err.Error(), "Unable to expand placeholder") {
			return false, errors.New("not in a GitLab repo; pass <group/project>")
		}
		return false, err
	}
	base := fmt.Sprintf("projects/%d/", proj.ID)
	branch := proj.DefaultBranch
	if len(args) >= 2 {
		branch = args[1]
	} else {
		// In develop/main (git-flow) projects, day-to-day merges target develop.
		var found []struct {
			Name string `json:"name"`
		}
		if err := glabGet(base+"repository/branches?search="+url.QueryEscape("^develop$"), &found); err != nil {
			return false, err
		}
		for _, b := range found {
			if b.Name == "develop" {
				branch = "develop"
			}
		}
	}

	var rules []protectedBranch
	switch {
	case proj.EmptyRepo && action == "merge":
		return false, errors.New("blank repository has no target branch; check push instead")
	case proj.EmptyRepo:
		entries, err := glabInitialPushAccess(proj.Namespace)
		if err != nil {
			return false, err
		}
		rules = []protectedBranch{{Name: branch, Push: entries}}
	default:
		var err error
		rules, err = glabList[protectedBranch](base + "protected_branches")
		if err != nil {
			return false, err
		}
	}
	all, err := glabList[member](base + "members/all")
	if err != nil {
		return false, err
	}
	var me member
	if err := glabGet("user", &me); err != nil {
		return false, err
	}

	projectMembers := effective(all)
	members := candidates(projectMembers, me)
	groups, err := glabGroupMembers(rules, branch, action)
	if err != nil {
		return false, err
	}
	v, err := decide(rules, members, branch, action, groups)
	if err != nil {
		return false, err
	}

	rule := "unprotected (Developers + Maintainers)"
	if v.Rule != "" {
		rule = "protected (" + v.Rule + ")"
	}
	fmt.Fprintf(out, "%s %s %s: %s\n", proj.Path, branch, action, rule)

	myRole := "not a member"
	for _, m := range projectMembers {
		if m.ID == me.ID {
			myRole = roles[m.AccessLevel]
		}
	}
	can := v.Administrators && me.IsAdmin && me.State == "active"
	var names []string
	for _, m := range v.Allowed {
		can = can || m.ID == me.ID
		if v.Administrators && m.IsAdmin {
			continue
		}
		names = append(names, fmt.Sprintf("%s (%s)", m.Username, roles[m.AccessLevel]))
	}
	if v.Administrators {
		names = append(names, "instance administrators")
	}
	verdict := "cannot"
	if can {
		verdict = "can"
	}
	fmt.Fprintf(out, "you: %s (%s), %s\n", me.Username, myRole, verdict)
	if len(names) == 0 {
		names = []string{"no one"}
	}
	fmt.Fprintf(out, "can: %s\n", strings.Join(names, ", "))
	if v.CodeOwners && action == "merge" {
		fmt.Fprintln(out, "note: code-owner approval is also required for owned paths; see CODEOWNERS")
	}
	return can, nil
}

func main() {
	can, err := run(os.Args[1:], os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "whocan:", err)
		os.Exit(2)
	}
	if !can {
		os.Exit(1)
	}
}
