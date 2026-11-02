package middleware

// Export unexported functions for testing.
var ExtractClaimsFromJWT = extractClaimsFromJWT

var BuildUserPolicy = buildUserPolicy
var ClearSessionCache = clearSessionCache
