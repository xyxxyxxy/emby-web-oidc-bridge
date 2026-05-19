---
inclusion: auto
---

# Project Context

## Project Name
emby-web-oidc-bridge

## Purpose
A self-hosted solution that bridges Emby web authentication with OpenID Connect (OIDC) providers, enabling centralized identity management for Emby instances.

## Key Characteristics
- **Self-hosted**: Designed to run locally without external dependencies
- **Docker-first**: Deployed via Docker Compose for consistency and reproducibility
- **Security-focused**: Handles authentication and OIDC flows
- **Pragmatic approach**: Uses external packages when they reduce complexity and improve maintainability
- **Local-first**: All components run on user's infrastructure

## Technology Stack
- Language: [To be determined - Node.js/Python/Go]
- Authentication: OpenID Connect (OIDC)
- Integration: Emby Media Server API

## Development Standards

### Version Control
- **Model**: Git-flow branching strategy
- **Main branches**: `main` (production), `develop` (integration)
- **Feature branches**: `feature/*`, `bugfix/*`, `hotfix/*`, `release/*`

### Commit Messages
- **Format**: Conventional Commits
- **Types**: feat, fix, docs, style, refactor, perf, test, chore, ci
- **Example**: `feat(oidc): add provider discovery` or `fix(auth): resolve token validation`

### Code Quality
- Self-documenting code with comments on complex logic
- Input validation for all user data and OIDC responses
- Error handling for external API calls
- No hardcoded secrets (use environment variables)
- Security-first approach to authentication flows

## Important Files
- `AGENT.md` - AI agent guidelines and project principles
- `DEVELOPMENT.md` - Local setup and development workflow
- `DOCKER.md` - Docker and Docker Compose deployment guide
- `README.md` - User-facing documentation
- `docker-compose.yml` - Production deployment configuration
- `Dockerfile` - Container image definition
- `.env.local` - Local development configuration (not committed)
- `.env.example` - Environment variables template

## When Working on This Project

1. **Always use git-flow**: Create feature branches from `develop`, not `main`
2. **Use conventional commits**: Format all commit messages properly
3. **Security first**: Validate all inputs, never log sensitive data
4. **Test with Docker Compose**: Use docker-compose for local testing
5. **Document changes**: Update relevant documentation files
6. **Environment variables**: Never hardcode configuration or secrets
7. **Multi-stage builds**: Optimize Docker images for production

## Common Tasks

- **Starting a feature**: `git flow feature start feature-name`
- **Committing**: `git commit -m "feat(scope): description"`
- **Finishing a feature**: `git flow feature finish feature-name`
- **Creating a release**: `git flow release start X.Y.Z`

## Security Considerations
- OIDC token validation is critical
- Emby API key must be protected
- HTTPS required in production
- CSRF protection needed
- Input sanitization mandatory
