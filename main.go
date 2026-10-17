// whocan reports who may merge into (or push to) a GitLab branch, from live
// API data, so a plan learns about a permission wall before it reaches it.
//
//	whocan <group/project> [branch] [merge|push]
//
// The branch defaults to the project's default branch, the action to merge.
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
	AccessLevel int    `json:"access_level"`
	Description string `json:"access_level_description"`
	UserID      *int   `json:"user_id"`
	GroupID     *int   `json:"group_id"`
	DeployKeyID *int   `json:"deploy_key_id"`
}

type protectedBranch struct {
	Name               string        `json:"name"`
	Push               []accessLevel `json:"push_access_levels"`
	Merge              []accessLevel `json:"merge_access_levels"`
	CodeOwnersRequired bool          `json:"code_owner_approval_required"`
}

type member struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	AccessLevel int    `json:"access_level"`
	State       string `json:"state"`
}

type verdict struct {
	Rule       string // "" when the branch is unprotected
	Allowed    []member
	CodeOwners bool
}

const developer = 30

var roles = map[int]string{10: "Guest", 15: "Planner", 20: "Reporter", 30: "Developer", 40: "Maintainer", 50: "Owner"}

// GitLab's only wildcard is `*`, and it spans `/` (`production/*`).
func matches(pattern, branch string) bool {
	re := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
	return regexp.MustCompile(re).MatchString(branch)
}

func permits(e accessLevel, m member) bool {
	switch {
	case e.DeployKeyID != nil:
		return false
	case e.UserID != nil:
		return *e.UserID == m.ID
	case e.AccessLevel == 0: // "No one"
		return false
	}
	return m.AccessLevel >= e.AccessLevel
}

// decide applies GitLab's rule: when several protected-branch rules match,
// the most permissive one controls the branch, so the allowed set is the union.
func decide(rules []protectedBranch, members []member, branch, action string) (verdict, error) {
	var matched []protectedBranch
	for _, r := range rules {
		if matches(r.Name, branch) {
			matched = append(matched, r)
		}
	}

	var v verdict
	var entries []accessLevel
	var descs []string
	if len(matched) == 0 {
		entries = []accessLevel{{AccessLevel: developer}}
	} else {
		v.CodeOwners = true
		for _, r := range matched {
			v.CodeOwners = v.CodeOwners && r.CodeOwnersRequired
			es := r.Merge
			if action == "push" {
				es = r.Push
			}
			for _, e := range es {
				if e.GroupID != nil {
					// Resolving group membership is not implemented; refuse rather than under-report.
					return v, fmt.Errorf("rule %q grants %s to a group, which whocan does not resolve", r.Name, action)
				}
				entries = append(entries, e)
				if !slices.Contains(descs, e.Description) {
					descs = append(descs, e.Description)
				}
			}
		}
		v.Rule = strings.Join(descs, ", ")
	}

	for _, m := range members {
		for _, e := range entries {
			if permits(e, m) {
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

func glabGet(endpoint string, v any) error {
	out, err := glab(endpoint)
	if err != nil {
		return err
	}
	return json.Unmarshal(out, v)
}

func run(args []string) (bool, error) {
	if len(args) < 1 || len(args) > 3 {
		return false, errors.New("usage: whocan <group/project> [branch] [merge|push]")
	}
	action := "merge"
	if len(args) == 3 {
		action = args[2]
	}
	if action != "merge" && action != "push" {
		return false, fmt.Errorf("action must be merge or push, got %q", action)
	}

	var proj struct {
		ID            int    `json:"id"`
		Path          string `json:"path_with_namespace"`
		DefaultBranch string `json:"default_branch"`
	}
	if err := glabGet("projects/"+url.PathEscape(args[0]), &proj); err != nil {
		return false, err
	}
	branch := proj.DefaultBranch
	if len(args) >= 2 {
		branch = args[1]
	}

	base := fmt.Sprintf("projects/%d/", proj.ID)
	rules, err := glabList[protectedBranch](base + "protected_branches")
	if err != nil {
		return false, err
	}
	all, err := glabList[member](base + "members/all")
	if err != nil {
		return false, err
	}
	var me member
	if err := glabGet("user", &me); err != nil {
		return false, err
	}

	members := effective(all)
	v, err := decide(rules, members, branch, action)
	if err != nil {
		return false, err
	}

	rule := "unprotected (Developers + Maintainers)"
	if v.Rule != "" {
		rule = "protected (" + v.Rule + ")"
	}
	fmt.Printf("%s %s %s: %s\n", proj.Path, branch, action, rule)

	myRole := "not a member"
	for _, m := range members {
		if m.ID == me.ID {
			myRole = roles[m.AccessLevel]
		}
	}
	can := false
	var names []string
	for _, m := range v.Allowed {
		names = append(names, fmt.Sprintf("%s (%s)", m.Username, roles[m.AccessLevel]))
		can = can || m.ID == me.ID
	}
	verdict := "cannot"
	if can {
		verdict = "can"
	}
	fmt.Printf("you: %s (%s), %s\n", me.Username, myRole, verdict)
	if len(names) == 0 {
		names = []string{"no one"}
	}
	fmt.Printf("can: %s\n", strings.Join(names, ", "))
	if v.CodeOwners && action == "merge" {
		fmt.Println("note: code-owner approval is also required for owned paths; see CODEOWNERS")
	}
	return can, nil
}

func main() {
	can, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "whocan:", err)
		os.Exit(2)
	}
	if !can {
		os.Exit(1)
	}
}
