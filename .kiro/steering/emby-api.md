---
inclusion: fileMatch
fileMatchPattern: "internal/emby/*"
---

# Emby API Reference

## Authentication

API key is passed as query parameter: `?api_key={key}`

For user authentication, use the `X-Emby-Authorization` header:
```
X-Emby-Authorization: Emby Client="EmbyAuthBridge", Device="Server", DeviceId="emby-auth-bridge", Version="1.0.0"
```

## Password Update (Two-Step)

Emby requires a two-step process to change a user's password:

1. **Reset** — POST `/Users/{Id}/Password?api_key={key}` with `{"Id": "...", "ResetPassword": true}`
2. **Set** — POST `/Users/{Id}/Password?api_key={key}` with `{"Id": "...", "NewPw": "newpassword"}`

Sending both `ResetPassword: true` and `NewPw` in one call does NOT work — Emby ignores `NewPw` when resetting.

## Endpoints Used

| Operation | Method | Path | Notes |
|-----------|--------|------|-------|
| Find user | GET | `/Users/Query?api_key=` | Returns `{"Items": [...]}`, filter by Name |
| Create user | POST | `/Users/New?api_key=` | Body: `{Name, CopyFromUserId, UserCopyOptions}` |
| Authenticate | POST | `/Users/AuthenticateByName` | Uses X-Emby-Authorization header, body: `{Username, Pw}` |
| Reset password | POST | `/Users/{Id}/Password?api_key=` | Body: `{Id, ResetPassword: true}` |
| Set password | POST | `/Users/{Id}/Password?api_key=` | Body: `{Id, NewPw: "..."}` |
| Update policy | POST | `/Users/{Id}/Policy?api_key=` | Body: policy JSON |
| Set image | POST | `/Users/{Id}/Images/Primary?api_key=` | Body: raw bytes, Content-Type: application/octet-stream |
| Health check | GET | `/System/Info?api_key=` | Any 2xx = healthy |

## User Policy Fields

```json
{
  "IsDisabled": false,
  "IsHidden": true,
  "EnableUserPreferenceAccess": false
}
```

- `IsHidden` = "Hide this user from login screens on the local network"
- `EnableUserPreferenceAccess` = prevents user from changing password/profile in Emby UI

## User Creation with Template

```json
{
  "Name": "user@example.com",
  "CopyFromUserId": "<template-user-id>",
  "UserCopyOptions": ["UserPolicy", "UserConfiguration"]
}
```

Note: `IsHidden` is NOT copied from the template user — it must be set explicitly via a policy update after creation.

## OpenAPI Spec

The full Emby OpenAPI spec is at `.kiro/references/emby-openapi.json` in the project. Reference it for endpoint details: #[[file:.kiro/references/emby-openapi.json]]
