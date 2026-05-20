# Requirements Document

## Introduction

The Emby Authentication Bridge is a lightweight service that enables seamless single sign-on for Emby's web interface via OIDC. It sits behind oauth2-proxy, which handles the actual OAuth2/OIDC authentication with the identity provider. The Bridge reads OIDC session headers from oauth2-proxy, auto-provisions users in Emby, authenticates them transparently, and provides a simple account page where users can view their generated credentials for use in Emby TV/mobile apps. Admin configuration is done entirely via environment variables — no admin UI is needed. The design prioritizes simplicity, minimal code, and low maintenance.

**Security Model:** Emby is expected to be hosted behind oauth2-proxy or a VPN for direct access. The generated password is not considered security-critical — it exists solely for TV/mobile app authentication where OAuth flows are not supported. The password format (8 lowercase alphanumeric characters) is chosen for easy entry on TV remotes and mobile app keyboards. Passwords are stored in plaintext in the database.

## Glossary

- **Bridge**: The Emby Authentication Bridge service that acts as an intermediary between oauth2-proxy and Emby
- **oauth2-proxy**: An external reverse proxy that handles OAuth2/OIDC authentication with the identity provider and sets forwarded headers
- **Emby**: The media server application being protected
- **X-Forwarded-Email**: HTTP header containing the authenticated user's email address, set by oauth2-proxy
- **X-Forwarded-User**: HTTP header containing the authenticated user's display name, set by oauth2-proxy
- **X-Forwarded-Picture**: HTTP header containing the authenticated user's profile image URL from OIDC claims, set by oauth2-proxy
- **User_Provisioning**: The process of creating a new Emby user account with generated credentials and template-based settings
- **Generated_Password**: A random password of exactly 8 characters consisting only of lowercase letters (a-z) and digits (0-9), generated during user provisioning and stored in plaintext. The format is optimized for easy entry on TV remotes and mobile app keyboards.
- **SQLite_Database**: Local database storing user records and metadata
- **Emby_API**: Emby's REST API for user management operations
- **Template_User**: A pre-configured Emby user whose settings and policy are copied to newly provisioned users
- **Account_Page**: A simple web interface displaying user credentials for TV/mobile app usage
- **Trusted_Proxies**: A whitelist of IP addresses or CIDR ranges from which the Bridge accepts forwarded headers; requests from other sources are rejected

## Requirements

### Requirement 1: Trusted Proxy and OIDC Header Integration

**User Story:** As a system administrator, I want the Bridge to only accept requests from trusted proxies and read OIDC session headers from oauth2-proxy, so that only authenticated users from the trusted proxy are recognized.

#### Acceptance Criteria

1. THE Bridge SHALL read the TRUSTED_PROXIES environment variable containing a comma-separated list of trusted IP addresses or CIDR ranges
2. WHEN a request arrives from an IP not in the trusted proxies list, THE Bridge SHALL reject the request with a 403 Forbidden response
3. WHEN a request arrives from a trusted proxy with an X-Forwarded-Email header, THE Bridge SHALL extract the email address from that header
4. WHEN a request arrives from a trusted proxy without an X-Forwarded-Email header, THE Bridge SHALL reject the request with a 401 Unauthorized response
5. WHEN a request arrives with an X-Forwarded-Picture header, THE Bridge SHALL extract the profile image URL from that header

---

### Requirement 2: User Existence Check

**User Story:** As the Bridge, I want to check if a user already exists in Emby, so that I can determine whether to provision a new account or authenticate an existing one.

#### Acceptance Criteria

1. WHEN a user email is extracted from the X-Forwarded-Email header, THE Bridge SHALL query the Emby_API to check if a user with that email as username exists
2. WHEN the Emby_API responds with a user record, THE Bridge SHALL recognize the user as existing
3. WHEN the Emby_API responds with no user record, THE Bridge SHALL recognize the user as non-existing and trigger User_Provisioning
4. WHEN the Emby_API is unreachable, THE Bridge SHALL return a 503 Service Unavailable response

---

### Requirement 3: User Provisioning with Generated Password

**User Story:** As the Bridge, I want to automatically create new Emby users with generated passwords optimized for TV/mobile input, so that users can access Emby immediately after OIDC authentication.

#### Acceptance Criteria

1. WHEN a user does not exist in Emby, THE Bridge SHALL generate a random password of exactly 8 characters consisting only of lowercase letters (a-z) and numbers (0-9)
2. WHEN a password is generated, THE Bridge SHALL create a new Emby user account with the email address as the username
3. WHEN a new user account is created, THE Bridge SHALL set the Generated_Password as the user's initial password in Emby
4. WHEN user creation succeeds, THE Bridge SHALL store the user record in the SQLite_Database with the plaintext password
5. WHEN user creation fails, THE Bridge SHALL return a 500 Internal Server Error response and log the failure reason
6. WHEN a user already exists in the SQLite_Database, THE Bridge SHALL use the existing stored password and SHALL NOT generate a new password

---

### Requirement 4: Template User Configuration

**User Story:** As a system administrator, I want new users to inherit settings and policy from a configured template user in Emby, so that I can manage default permissions without code changes.

#### Acceptance Criteria

1. THE Bridge SHALL read the TEMPLATE_USER_NAME environment variable to identify the Template_User in Emby
2. WHEN a new user is provisioned, THE Bridge SHALL pass the Template_User's ID as CopyFromUserId in the Emby_API user creation request with UserCopyOptions set to UserPolicy and UserConfiguration
3. WHEN the Template_User does not exist in Emby, THE Bridge SHALL fail to start and log an error message
4. WHEN the new user is created from a disabled Template_User, THE Bridge SHALL override the disabled flag and set the new user as enabled
5. WHEN user creation with template fails, THE Bridge SHALL log the failure and return a 500 Internal Server Error response

---

### Requirement 5: Disable User Preference Access

**User Story:** As a system administrator, I want users to be unable to change their password or profile image in Emby, so that credentials remain managed by the Bridge and profile images stay synced with OIDC.

#### Acceptance Criteria

1. WHEN a user logs in via the Bridge, THE Bridge SHALL set the EnableUserPreferenceAccess policy to false for that user via the Emby_API
2. WHEN the EnableUserPreferenceAccess policy update fails, THE Bridge SHALL log the failure

---

### Requirement 6: Profile Image Sync from OIDC

**User Story:** As a user, I want my OIDC profile image to be used as my Emby profile image, so that my identity is consistent across services.

#### Acceptance Criteria

1. WHEN a user logs in and the X-Forwarded-Picture header contains a valid URL, THE Bridge SHALL set that URL as the user's profile image in Emby via the Emby_API
2. WHEN the X-Forwarded-Picture header is absent or empty, THE Bridge SHALL not modify the user's profile image
3. WHEN the profile image update fails, THE Bridge SHALL log the failure and continue the login flow

---

### Requirement 7: Seamless Emby Web Login

**User Story:** As a user, I want to access the Emby web interface without entering a username or password, so that my OIDC session provides seamless authentication.

#### Acceptance Criteria

1. WHEN a user is authenticated via X-Forwarded-Email, THE Bridge SHALL authenticate with Emby using the user's stored password
2. WHEN authentication with Emby succeeds, THE Bridge SHALL proxy the user's requests to Emby with the authenticated session
3. WHEN proxying requests, THE Bridge SHALL preserve request headers and body content
4. WHEN authentication with Emby fails, THE Bridge SHALL attempt to re-authenticate using the stored password
5. IF re-authentication fails, THEN THE Bridge SHALL return a 401 Unauthorized response
6. WHEN a user exists in Emby but does not have a record in the SQLite_Database (first login via the Bridge), THE Bridge SHALL generate a new password, update it in Emby, and store it in the database

---

### Requirement 8: Account Page for TV/Mobile Credentials

**User Story:** As a user, I want to view my generated Emby username and password on a simple web page, so that I can use them to log in on Emby TV and mobile apps.

#### Acceptance Criteria

1. WHEN a user accesses the account page, THE Bridge SHALL display the user's username (email address)
2. WHEN a user accesses the account page, THE Bridge SHALL display the user's plaintext password from the database
3. WHEN the account page is accessed, THE Bridge SHALL verify the user is authenticated via the X-Forwarded-Email header
4. WHEN an unauthenticated user attempts to access the account page, THE Bridge SHALL return a 401 Unauthorized response

---

### Requirement 9: SQLite Database Schema

**User Story:** As the Bridge, I want to store user records persistently, so that user provisioning data survives service restarts.

#### Acceptance Criteria

1. THE Bridge SHALL create a SQLite_Database with a users table containing: email, emby_user_id, password, created_at
2. WHEN the Bridge starts, THE Bridge SHALL initialize the database schema if it does not exist
3. WHEN a user is provisioned, THE Bridge SHALL insert a record into the users table with the email, emby_user_id, and plaintext password
4. WHEN the database file is corrupted or inaccessible, THE Bridge SHALL fail to start and log an error message

---

### Requirement 10: Emby API Integration

**User Story:** As the Bridge, I want to interact with Emby's REST API, so that I can manage users, policies, and profile images programmatically.

#### Acceptance Criteria

1. WHEN the Bridge needs to check if a user exists, THE Bridge SHALL call the Emby_API user lookup endpoint
2. WHEN the Bridge needs to create a user, THE Bridge SHALL call the Emby_API user creation endpoint with email and password
3. WHEN the Bridge needs to apply a policy, THE Bridge SHALL call the Emby_API policy endpoint with the Template_User's settings
4. WHEN the Bridge needs to update a password, THE Bridge SHALL call the Emby_API password update endpoint
5. WHEN the Bridge needs to set a profile image, THE Bridge SHALL call the Emby_API profile image endpoint
6. WHEN an Emby_API call fails with a 4xx error, THE Bridge SHALL log the error and return an appropriate HTTP response
7. WHEN an Emby_API call fails with a 5xx error, THE Bridge SHALL log the error and return a 503 Service Unavailable response

---

### Requirement 11: Environment Configuration

**User Story:** As a system administrator, I want to configure the Bridge entirely via environment variables, so that I can deploy it in different environments without code changes and without needing an admin UI.

#### Acceptance Criteria

1. THE Bridge SHALL read the EMBY_API_URL environment variable for the Emby API endpoint
2. THE Bridge SHALL read the EMBY_API_KEY environment variable for Emby API authentication
3. THE Bridge SHALL read the TEMPLATE_USER_NAME environment variable for the Template_User to copy settings from
4. THE Bridge SHALL read the TRUSTED_PROXIES environment variable containing a comma-separated list of trusted IP addresses or CIDR ranges
5. THE Bridge SHALL read the BRIDGE_PORT environment variable for the port the Bridge listens on (default: 8080)
6. THE Bridge SHALL read the DATABASE_PATH environment variable for the SQLite database file location (default: ./users.db)
7. WHEN a required environment variable (EMBY_API_URL, EMBY_API_KEY, TEMPLATE_USER_NAME, TRUSTED_PROXIES) is missing, THE Bridge SHALL fail to start and log which variable is missing

---

### Requirement 12: Logging

**User Story:** As a system administrator, I want structured logging of Bridge operations, so that I can troubleshoot issues and audit security events.

#### Acceptance Criteria

1. WHEN a user is provisioned, THE Bridge SHALL log the email address, timestamp, and success/failure status
2. WHEN an authentication failure occurs, THE Bridge SHALL log the reason and timestamp
3. WHEN an Emby_API error occurs, THE Bridge SHALL log the endpoint, error code, and error message
4. WHEN a database error occurs, THE Bridge SHALL log the operation, error message, and timestamp

---

### Requirement 13: Docker Containerization

**User Story:** As a system administrator, I want to deploy the Bridge in Docker, so that it can be easily integrated into a Docker Compose environment.

#### Acceptance Criteria

1. THE Bridge SHALL be packaged as a Docker image with all dependencies included
2. WHEN the Docker container starts, THE Bridge SHALL read environment variables from the container environment
3. WHEN the Docker container starts, THE Bridge SHALL initialize the SQLite_Database if it does not exist
4. THE Bridge SHALL expose port 8080 (or configured BRIDGE_PORT) for incoming requests
5. THE Bridge SHALL mount a volume for persistent SQLite_Database storage

---

### Requirement 14: Health Check Endpoint

**User Story:** As a system administrator, I want to check the health of the Bridge, so that I can monitor its availability and detect failures.

#### Acceptance Criteria

1. WHEN a GET request is made to /health, THE Bridge SHALL return a 200 OK response
2. WHEN the /health endpoint is called, THE Bridge SHALL verify connectivity to the SQLite_Database
3. WHEN the /health endpoint is called, THE Bridge SHALL verify connectivity to the Emby_API
4. WHEN the database is unreachable, THE Bridge SHALL return a 503 Service Unavailable response from /health
5. WHEN the Emby_API is unreachable, THE Bridge SHALL return a 503 Service Unavailable response from /health
