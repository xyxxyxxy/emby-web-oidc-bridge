package middleware

// Export unexported functions for testing.
var ExtractClaimsFromJWT = extractClaimsFromJWT

// ExtractPictureFromJWT is a compatibility wrapper for tests that only need the picture claim.
func ExtractPictureFromJWT(token string) string {
	_, _, _, picture := extractClaimsFromJWT(token)
	return picture
}

var BuildUserPolicy = buildUserPolicy
var ClearSessionCache = clearSessionCache
