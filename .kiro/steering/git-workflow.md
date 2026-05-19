---
inclusion: manual
---

# Git Workflow Guide

This guide provides detailed instructions for working with git-flow and conventional commits in this project.

## Git-Flow Quick Reference

### Initialize Git-Flow
```bash
git flow init
# Accept all defaults or customize as needed
```

### Feature Development

**Start a feature:**
```bash
git flow feature start my-feature
# Creates and checks out: feature/my-feature
```

**Work on the feature:**
```bash
# Make changes and commit with conventional commits
git commit -m "feat(scope): description of change"
git commit -m "fix(scope): fix something in the feature"
```

**Finish the feature:**
```bash
git flow feature finish my-feature
# Merges to develop with --no-ff flag
# Deletes the feature branch
```

### Bug Fixes

**Start a bugfix:**
```bash
git flow bugfix start issue-name
# Creates: bugfix/issue-name
```

**Finish the bugfix:**
```bash
git flow bugfix finish issue-name
# Merges to develop
```

### Releases

**Start a release:**
```bash
git flow release start 1.0.0
# Creates: release/1.0.0
```

**Update version numbers:**
- Edit `package.json` (or equivalent)
- Update `CHANGELOG.md`
- Commit: `git commit -m "chore(release): bump version to 1.0.0"`

**Finish the release:**
```bash
git flow release finish 1.0.0
# Merges to main and develop
# Creates tag v1.0.0
# Prompts for tag message
```

### Hotfixes

**Start a hotfix:**
```bash
git flow hotfix start 1.0.1
# Creates: hotfix/1.0.1
```

**Make the fix:**
```bash
git commit -m "fix(security): patch critical vulnerability"
```

**Finish the hotfix:**
```bash
git flow hotfix finish 1.0.1
# Merges to main and develop
# Creates tag v1.0.1
```

## Conventional Commits Format

### Basic Structure
```
<type>(<scope>): <subject>

<body>

<footer>
```

### Type
- `feat` - A new feature
- `fix` - A bug fix
- `docs` - Documentation only changes
- `style` - Changes that don't affect code meaning (formatting, semicolons, etc.)
- `refactor` - Code change that neither fixes a bug nor adds a feature
- `perf` - Code change that improves performance
- `test` - Adding missing tests or correcting existing tests
- `chore` - Changes to build process, dependencies, or tooling
- `ci` - Changes to CI/CD configuration

### Scope
Optional but recommended. Indicates what part of the codebase is affected:
- `oidc` - OIDC provider integration
- `auth` - Authentication logic
- `emby` - Emby API integration
- `config` - Configuration handling
- `api` - API endpoints
- `ui` - User interface
- `deps` - Dependencies

### Subject
- Use imperative mood ("add" not "added" or "adds")
- Don't capitalize first letter
- No period (.) at the end
- Limit to 50 characters

### Body
- Optional but recommended for non-trivial changes
- Explain what and why, not how
- Wrap at 72 characters
- Separate from subject with blank line

### Footer
- Optional
- Reference issues: `Fixes #123`, `Closes #456`
- Breaking changes: `BREAKING CHANGE: description`

### Examples

**Simple feature:**
```
feat(oidc): add provider discovery endpoint
```

**Feature with body:**
```
feat(auth): implement token refresh mechanism

Add automatic token refresh before expiration to prevent
authentication failures during long sessions. Tokens are
refreshed 5 minutes before expiration.

Fixes #42
```

**Bug fix:**
```
fix(auth): resolve token validation timing issue

The token validation was checking expiration against the
wrong timestamp, causing valid tokens to be rejected.
```

**Documentation:**
```
docs(setup): add OIDC provider configuration guide
```

**Chore:**
```
chore(deps): upgrade express to 4.18.0
```

**Breaking change:**
```
feat(api): change authentication endpoint response format

BREAKING CHANGE: The /auth endpoint now returns tokens
in a nested 'data' object instead of at the root level.
```

## Workflow Example

### Scenario: Adding OIDC Provider Support

```bash
# 1. Start from develop
git checkout develop
git pull origin develop

# 2. Create feature branch
git flow feature start oidc-provider-support

# 3. Make changes and commit
git commit -m "feat(oidc): add provider configuration schema"
git commit -m "feat(oidc): implement provider discovery"
git commit -m "test(oidc): add provider discovery tests"

# 4. Push to remote (if working with others)
git push origin feature/oidc-provider-support

# 5. Create pull request on GitHub/GitLab
# (Link to issue if applicable)

# 6. After review and approval, finish feature
git flow feature finish oidc-provider-support

# 7. Push develop to remote
git push origin develop
```

### Scenario: Fixing a Production Bug

```bash
# 1. Start hotfix from main
git flow hotfix start 1.0.1

# 2. Make the fix
git commit -m "fix(security): patch token validation vulnerability"

# 3. Finish hotfix
git flow hotfix finish 1.0.1

# 4. Push tags and branches
git push origin main develop
git push origin --tags
```

## Tips and Best Practices

1. **Commit often**: Make small, focused commits that are easy to review and revert if needed
2. **Write good messages**: Clear commit messages help with debugging and history
3. **Keep branches short-lived**: Finish features quickly to avoid merge conflicts
4. **Pull before push**: Always pull latest changes before pushing
5. **Use branches for everything**: Never commit directly to `main` or `develop`
6. **Review before merging**: Have someone review your code before merging
7. **Tag releases**: Always tag releases for easy reference and rollback

## Troubleshooting

**Merge conflicts during feature finish:**
```bash
# Resolve conflicts in your editor
git add .
git commit -m "Merge branch 'develop' into feature/my-feature"
git flow feature finish my-feature
```

**Accidentally committed to wrong branch:**
```bash
# Create a new branch from current state
git branch feature/my-feature

# Reset current branch to before the commit
git reset --hard HEAD~1

# Switch to the feature branch
git checkout feature/my-feature
```

**Need to update feature with latest develop:**
```bash
git checkout feature/my-feature
git pull origin develop
# Resolve any conflicts
git push origin feature/my-feature
```
