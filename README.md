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

Requires Go 1.22+ and an authenticated [glab](https://gitlab.com/gitlab-org/cli)
(self-hosted GitLab works via `GITLAB_HOST`).

```
go install github.com/gengwg/whocan@latest
```

## Usage

```
whocan [group/project] [branch] [merge|push]
```

With no arguments it checks the repo in the current directory. The branch
defaults to `develop` if the project has one (git-flow), else the project's
default branch. The action defaults to `merge`.
Exit status is 0 if you can, 1 if you cannot, 2 on error, so scripts can check
before planning a merge.

It applies GitLab's rules: wildcard protected branches, the most permissive
matching access rule winning, push access also granting merge access, the most
restrictive matching Code Owner rule winning, user-specific and direct-group
grants, and effective (inherited) member roles. Group grants require active
Developer-or-higher membership in the granted group itself. Access-token bot
users are hidden.

## Limits

- GitLab only.
- It checks who may merge into the branch, not whether a given MR can merge.
  Required approvals (including Code Owners) and pipelines that must pass can
  still block the merge. When Code Owner approval is required, whocan prints a
  note.
- For pushes, it checks the branch grant only; push rules and other repository
  policies can still reject a push.
- Rules that grant access to a custom role are reported as an error rather than
  resolved.
