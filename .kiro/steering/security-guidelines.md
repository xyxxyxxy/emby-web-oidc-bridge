---
inclusion: manual
---

# Security Guidelines

This document outlines security best practices for the emby-web-oidc-bridge project.

## Authentication & OIDC

### Token Handling
- **Never log tokens**: Tokens contain sensitive information and should never appear in logs
- **Validate signatures**: Always validate OIDC token signatures against the provider's public key
- **Check expiration**: Verify token expiration before using
- **Validate issuer**: Ensure token issuer matches configured OIDC provider
- **Validate audience**: Verify the token's audience claim matches this application

### Token Storage
- Store tokens securely (encrypted if persisted)
- Use secure, HTTP-only cookies for session tokens
- Implement token refresh before expiration
- Clear tokens on logout

### OIDC Provider Configuration
- Use HTTPS for all OIDC provider communication
- Validate provider certificates in production
- Store client secrets securely (environment variables, not code)
- Use strong client secrets (minimum 32 characters)

## Input Validation

### User Input
- Validate all user-provided data
- Sanitize inputs before using in queries or responses
- Reject unexpected data types
- Implement length limits on all inputs

### OIDC Responses
- Validate all claims in OIDC tokens
- Verify required claims are present
- Check claim data types and formats
- Reject tokens with unexpected structure

### Emby API Responses
- Validate responses from Emby API
- Handle error responses gracefully
- Don't trust user IDs from OIDC without verification

## Secrets Management

### Environment Variables
- Use `.env.local` for local development (never commit)
- Use `.env.example` to document required variables
- Never hardcode secrets in code
- Rotate secrets regularly

### Required Secrets
- `OIDC_CLIENT_SECRET` - OIDC provider client secret
- `EMBY_API_KEY` - Emby server API key
- Session encryption key (if applicable)

### Secret Rotation
- Implement graceful secret rotation
- Support multiple valid secrets during transition
- Log secret rotation events (without logging the secrets)

## HTTPS & Transport Security

### Production Requirements
- Always use HTTPS in production
- Use valid SSL/TLS certificates
- Implement HSTS headers
- Disable HTTP in production

### Development
- Use HTTP for local development
- Use self-signed certificates if testing HTTPS locally
- Never deploy development certificates to production

## CSRF Protection

### Implementation
- Use CSRF tokens for state-changing operations
- Validate CSRF tokens on all POST/PUT/DELETE requests
- Use SameSite cookie attribute
- Implement proper CORS headers

### OIDC State Parameter
- Generate random state parameter for OIDC authorization
- Validate state parameter in callback
- Use cryptographically secure random generation

## Logging & Monitoring

### What to Log
- Authentication attempts (success and failure)
- Authorization decisions
- Configuration changes
- Errors and exceptions

### What NOT to Log
- Tokens or token fragments
- Passwords or secrets
- API keys
- User credentials
- Sensitive claim values

### Log Security
- Store logs securely
- Implement log rotation
- Restrict log access
- Monitor logs for suspicious activity

## API Security

### Rate Limiting
- Implement rate limiting on authentication endpoints
- Prevent brute force attacks
- Use exponential backoff for retries

### Error Messages
- Don't reveal sensitive information in error messages
- Use generic error messages for authentication failures
- Log detailed errors internally

### CORS Configuration
- Whitelist allowed origins
- Restrict allowed methods
- Validate origin headers

## Dependency Security

### Dependency Management
- Keep dependencies up to date
- Monitor for security vulnerabilities
- Use tools like `npm audit` or `pip audit`
- Review dependency licenses

### Vulnerable Dependencies
- Address high-severity vulnerabilities immediately
- Test updates thoroughly before deploying
- Document any known vulnerabilities

## Code Review Checklist

When reviewing code, check for:

- [ ] No hardcoded secrets or credentials
- [ ] All user inputs are validated
- [ ] OIDC tokens are validated properly
- [ ] No sensitive data in logs
- [ ] Error handling is appropriate
- [ ] HTTPS is enforced in production
- [ ] CSRF protection is implemented
- [ ] Dependencies are up to date
- [ ] No SQL injection vulnerabilities
- [ ] No XSS vulnerabilities
- [ ] Proper authentication checks
- [ ] Proper authorization checks

## Incident Response

### Security Issues
- Report security issues privately (don't create public issues)
- Include reproduction steps
- Include affected versions
- Allow time for patch development

### Vulnerability Disclosure
- Follow responsible disclosure practices
- Provide reasonable time for fixes (typically 90 days)
- Coordinate public disclosure timing

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OpenID Connect Security Best Practices](https://openid.net/specs/openid-connect-core-1_0.html#Security)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
