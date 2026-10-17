# whocan

Who can merge into (or push to) a GitLab branch? Answers from live API data, so
you find a permission wall before you hit it at the merge button.

```
$ whocan mygroup/myproject
mygroup/myproject main merge: protected (Maintainers)
you: alice (Developer), cannot
can: bob (Maintainer), carol (Owner)
```

## Install

Requires Go and an authenticated [glab](https://gitlab.com/gitlab-org/cli)
(self-hosted GitLab works via `GITLAB_HOST`).

```
go install github.com/gengwg/whocan@latest
```

## Usage

```
whocan <group/project> [branch] [merge|push]
```

The branch defaults to `develop` if the project has one (git-flow), else the
project's default branch. The action defaults to `merge`.
Exit status is 0 if you can, 1 if you cannot, 2 on error, so scripts can check
before planning a merge.

It applies GitLab's rules: wildcard protected branches, the most permissive
matching rule winning, user-specific grants, and effective (inherited) member
roles. Access-token bot users are hidden.

## Limits

- GitLab only.
- CODEOWNERS is not evaluated. When a branch requires code-owner approval,
  whocan prints a note; the approval may still be needed.
- Rules that grant access to a group are reported as an error rather than
  resolved.
