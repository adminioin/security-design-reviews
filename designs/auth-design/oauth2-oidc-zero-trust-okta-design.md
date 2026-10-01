# OAuth2/OIDC Zero Trust Architecture with Okta

**Design Category**: Authentication & Identity  
**Date**: October 2026  
**Status**: Under Review  
**Author**: AK (Security Architecture)

---

## 1. Design Overview

### Summary
Enterprise identity architecture leveraging OAuth2/OIDC with Okta as the identity provider, implementing Zero Trust principles for a multi-cloud SaaS platform serving 10,000+ users across 50+ organizations.

### Current State
- Legacy SAML-based federation with on-premises Active Directory
- Basic role-based access control (RBAC)
- Limited device posture checking
- Monolithic application architecture

### Target State
- Modern OAuth2/OIDC flows with Okta
- Continuous identity verification
- Device trust and conditional access
- Micro-segmented API architecture
- Automated compliance monitoring

---

## 2. Design Details

### 2.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    External Users/Partners                   │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
        ┌────────────────────────┐
        │   Okta Authorization   │
        │      Server (Prod)     │
        │  - OAuth2/OIDC Flows   │
        │  - MFA Enforcement     │
        │  - Device Trust        │
        └────────────┬───────────┘
                     │
        ┌────────────┴──────────────┬──────────────┐
        │                           │              │
        ▼                           ▼              ▼
    ┌────────┐              ┌────────────┐   ┌──────────┐
    │ API    │              │ SPA/Mobile │   │ On-Prem  │
    │Gateway │              │ Apps       │   │ Resources│
    │(mTLS)  │              │(Bearer JWT)│   │(SAML2)   │
    └────────┘              └────────────┘   └──────────┘
```

### 2.2 OAuth2 Flow - Authorization Code with PKCE

**For Web/Mobile Apps:**

```
1. User initiates login
2. App redirects to Okta /authorize endpoint with:
   - client_id
   - redirect_uri
   - scope (openid profile email)
   - state (CSRF token)
   - code_challenge (PKCE)

3. Okta presents login + MFA prompt
   - Username/Password
   - TOTP/Push notification
   - Device compliance check

4. User grants consent

5. Okta redirects to app with:
   - authorization_code
   - state

6. App validates state, exchanges code for tokens:
   - POST /token with code_verifier (PKCE)
   - Receive: id_token, access_token, refresh_token

7. App validates id_token JWT signature
8. App uses access_token for API calls
```

### 2.3 OIDC Token Structure

**ID Token (JWT):**
```json
{
  "iss": "https://company.okta.com",
  "sub": "user@company.com",
  "aud": "client_id_12345",
  "exp": 1664567890,
  "iat": 1664564290,
  "auth_time": 1664564200,
  "email": "user@company.com",
  "email_verified": true,
  "name": "John Doe",
  "org_id": "org_123",
  "department": "Engineering",
  "groups": ["engineering", "security-team"]
}
```

**Access Token (JWT):**
```json
{
  "iss": "https://company.okta.com",
  "sub": "user@company.com",
  "aud": "api://company-api",
  "exp": 1664568000,
  "iat": 1664564400,
  "scope": "openid profile email api:read api:write",
  "org_id": "org_123",
  "device_id": "device_abc123",
  "client_id": "client_id_12345"
}
```

### 2.4 API Gateway Authentication (mTLS + Bearer Token)

**Request Flow:**
```
Client App
    │
    ├─ TLS Handshake (mutual certificate validation)
    │
    ├─ HTTP Request:
    │    Authorization: Bearer {access_token}
    │    X-Device-Id: device_abc123
    │    X-Nonce: unique_request_id
    │
    ▼
API Gateway
    │
    ├─ Validate mTLS certificate
    ├─ Validate Bearer token signature
    ├─ Check token expiration
    ├─ Verify device compliance
    ├─ Rate limiting (per user/device)
    │
    ▼ (if all pass)
Microservice
```

### 2.5 Device Trust & Conditional Access

**Device Posture Check:**
- Device must have MDM enrollment
- OS security patches up-to-date
- Disk encryption enabled
- No jailbreak/root detection
- Device IP geo-fencing (optional)

**Conditional Access Policies:**
```
IF location = "new_country"
   AND time = "off-hours"
   AND device_risk = "high"
THEN require = "step-up MFA" (hardware key)
ELSE allow = "normal access"
```

### 2.6 Token Management

**Refresh Token Rotation:**
- Refresh tokens valid for 30 days
- Each refresh returns new refresh token
- Old refresh token invalidated (rotation)
- Leaked token detection via anomaly scoring

**Token Revocation:**
- User logout triggers token revocation
- Device deregistration revokes all tokens
- Compromised token can be manually revoked

### 2.7 Logout & Session Termination

**Logout Flow:**
```
1. User clicks logout in app
2. App clears local tokens (id_token, access_token)
3. App redirects to Okta /logout endpoint
4. Okta invalidates session cookie
5. Okta clears active sessions
6. User redirected to app login page
```

---

## 3. Threat Model & Security Analysis

### 3.1 STRIDE Analysis

#### **S - Spoofing (Identity)**
**Threat**: Attacker impersonates legitimate user  
**Current Controls**:
- OAuth2 state parameter (CSRF prevention)
- JWT signature validation
- MFA enforcement (TOTP/Push)
- Device trust verification

**Gaps**:
- [ ] Token binding to device not implemented
- [ ] No account lockout after failed MFA
- [ ] Refresh token not bound to client_id

#### **T - Tampering (Data Integrity)**
**Threat**: Attacker modifies tokens, API requests, or auth parameters  
**Current Controls**:
- HTTPS/TLS for all communication
- JWT signature validation (HS256/RS256)
- PKCE prevents authorization code interception
- Request signing on API calls

**Gaps**:
- [ ] No request body signing (only headers)
- [ ] Replay attack protection incomplete
- [ ] Token not pinned to device

#### **R - Repudiation (Accountability)**
**Threat**: User denies performing an action  
**Current Controls**:
- Okta audit logs all auth events
- Access token logs include user/device/ip
- API gateway logs all requests

**Gaps**:
- [ ] Audit logs not immutable (can be deleted)
- [ ] No non-repudiation signing on sensitive actions
- [ ] Retention policy undefined

#### **I - Information Disclosure (Confidentiality)**
**Threat**: Attacker intercepts tokens, credentials, or sensitive data  
**Current Controls**:
- TLS 1.3 for all channels
- Tokens transmitted only over HTTPS
- No credentials in URLs/logs
- Encrypted secrets in Okta Vault

**Gaps**:
- [ ] Token stored in localStorage (XSS vulnerable)
- [ ] No Content Security Policy headers
- [ ] Tokens logged in error messages
- [ ] Refresh token not HttpOnly/Secure

#### **D - Denial of Service (Availability)**
**Threat**: Attacker floods auth server or exhausts resources  
**Current Controls**:
- Rate limiting on auth endpoints (10 req/min per IP)
- MFA delays failed login attempts
- Okta DDoS protection (Akamai)

**Gaps**:
- [ ] No per-user rate limit (account enumeration risk)
- [ ] Token refresh not rate-limited
- [ ] No circuit breaker for cascading failures
- [ ] Okta outage = total auth failure

#### **E - Elevation of Privilege (Authorization)**
**Threat**: Attacker gains higher privileges than authorized  
**Current Controls**:
- JWT includes user roles/groups
- API enforces RBAC on every request
- Admin actions require additional MFA

**Gaps**:
- [ ] Groups/roles not re-verified per request
- [ ] No attribute-based access control (ABAC)
- [ ] No real-time permission revocation
- [ ] Privilege escalation paths not documented

### 3.2 Attack Scenarios

**Scenario 1: Token Theft via XSS**
```
Attacker injects <script> into SPA
Script steals id_token from localStorage
Attacker uses token to call APIs as the user
Impact: Full account compromise
Risk Level: HIGH
```

**Scenario 2: Refresh Token Replay**
```
Attacker intercepts refresh_token in network
Device goes offline, attacker uses token
Attacker gets new access_token without MFA
Impact: Persistent unauthorized access
Risk Level: CRITICAL
```

**Scenario 3: Compromised API Key**
```
Client secret leaked in GitHub repo
Attacker uses secret to request tokens
Attacker gains access to all APIs
Impact: Data breach
Risk Level: CRITICAL
```

**Scenario 4: Session Fixation**
```
Attacker tricks user into using attacker's session
User logs in with state=attacker_controlled
Attacker gets authorization code
Impact: Account takeover
Risk Level: HIGH
```

---

## 4. Security Checklist

| Category | Control | Status | Notes |
|----------|---------|--------|-------|
| **Authentication** | MFA enforced for all users | ❌ | Only for admins |
| | PKCE enabled for native apps | ✅ | Configured |
| | Token expiration set (< 1 hour) | ❌ | 8 hour expiry |
| | Refresh token rotation enabled | ❌ | Not implemented |
| **Authorization** | RBAC implemented | ⚠️ | Basic roles only |
| | Resource-level access control | ❌ | Tenant-level only |
| | Admin privilege separation | ✅ | Configured |
| | Audit logging enabled | ✅ | 90-day retention |
| **Data Protection** | TLS 1.3 for all channels | ✅ | Configured |
| | Encryption at rest (tokens) | ⚠️ | Partial |
| | Secret rotation policy | ❌ | No policy |
| | PII data masking | ❌ | Logged in plaintext |
| **Network** | Network segmentation | ⚠️ | Partial |
| | mTLS for service-to-service | ❌ | No mTLS |
| | VPC endpoint for Okta API | ❌ | Not configured |
| | IP whitelisting | ⚠️ | Only for admin |
| **Monitoring** | Real-time alerting | ❌ | No alerts |
| | Anomaly detection | ⚠️ | Okta default only |
| | Token compromise detection | ❌ | No detection |
| | Audit log analysis | ❌ | No SIEM integration |

---

## 5. Compliance & Standards Alignment

| Standard | Requirement | Status | Gap |
|----------|-------------|--------|-----|
| **SOC 2** | Unique user identification | ✅ | Met |
| | Access control enforcement | ⚠️ | Partial |
| | Audit trail maintenance | ✅ | Met |
| **GDPR** | Consent for data processing | ✅ | Met |
| | Right to access/deletion | ❌ | No automation |
| | Data retention limits | ❌ | 90 days in logs |
| **HIPAA** | User authentication/authorization | ⚠️ | Partial |
| | Audit controls | ✅ | Met |
| | Encryption in transit | ✅ | Met |
| **NIST CSF** | Identity & Access Management | ⚠️ | Partial |
| | Asset Management | ❌ | No inventory |
| | Continuous Monitoring | ⚠️ | Partial |

---

## 6. Implementation Considerations

### 6.1 Deployment Scenarios

**Scenario A: Greenfield SaaS**
- Duration: 8-12 weeks
- Okta configuration from scratch
- No legacy system migration
- Risk: Low

**Scenario B: Brownfield Migration**
- Duration: 12-16 weeks
- Parallel run with legacy SAML
- Gradual user migration
- Risk: Medium (coordination complexity)

**Scenario C: Multi-Tenant Enterprise**
- Duration: 16-20 weeks
- Tenant isolation enforcement
- Okta org per tenant (or sub-domain)
- Risk: High (isolation failures)

### 6.2 Rollout Plan

```
Week 1-2:   Okta tenant setup, pilot group (10 users)
Week 3-4:   Internal IT team + QA
Week 5-8:   Phased rollout (25% users/week)
Week 9-12:  Full production + monitoring
Week 13-16: Legacy system decommission
```

### 6.3 Rollback Strategy

**Triggers:**
- > 5% auth failure rate
- Okta service degradation
- Critical security finding

**Steps:**
1. Activate legacy SAML IdP
2. Update DNS TTL (60 seconds before switchover)
3. Failover in 5-10 minutes
4. Notify users of temporary degradation

---

## 7. Monitoring & Alerting

### 7.1 Key Metrics

```
- Auth Success Rate: target > 99.9%
- MFA Adoption: target > 95%
- Average Login Time: target < 2 seconds
- Token Expiry Violations: target = 0
- Suspicious Login Attempts: monitor baseline
```

### 7.2 Logging Strategy

**Events to Log:**
- Successful/failed authentication
- MFA challenges and results
- Token issuance/refresh/revocation
- Admin actions (group changes, policy updates)
- Suspicious activities (geo-impossible logins)

**Log Retention:**
- Okta audit logs: 1 year (immutable)
- Application logs: 90 days
- Archive to S3 for compliance

### 7.3 Alerting Rules

```
Alert if:
- Failed MFA attempts > 10 in 5 min (per user)
- Geo-impossible login (e.g., NYC → Tokyo in 30 min)
- Token refresh from unknown device
- Client secret used from unexpected IP
- Refresh token reuse (rotation failure)
```

---

## 8. Questions for Reviewers

1. **Device Trust**: Should we implement mutual TLS (mTLS) between apps and API gateway?
2. **Token Binding**: How critical is binding tokens to device identity?
3. **Okta Redundancy**: Should we implement a backup IdP (e.g., PingOne) for high availability?
4. **On-Premises Integration**: What's the strategy for legacy on-prem systems requiring SAML?
5. **Tenant Isolation**: For multi-tenant SaaS, should we use separate Okta orgs or single org with sub-domains?
6. **Refresh Token Security**: Should refresh tokens be stored server-side (session-based) vs. client-side (stateless)?
7. **Step-Up Authentication**: When should we require additional MFA (sensitive APIs, permission changes)?
8. **Compliance Reporting**: Which compliance frameworks are critical (SOC 2, HIPAA, GDPR)?

---

## 9. References & Links

- [OAuth 2.0 Security Best Practices (RFC 6819)](https://tools.ietf.org/html/rfc6819)
- [OIDC Core Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE (RFC 7636)](https://tools.ietf.org/html/rfc7636)
- [Okta API Documentation](https://developer.okta.com/docs/)
- [NIST SP 800-63B: Authentication & Lifecycle](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP OAuth 2.0 Threat Model](https://tools.ietf.org/html/draft-ietf-oauth-threat-model)
- [Zero Trust Architecture (NIST SP 800-207)](https://csrc.nist.gov/publications/detail/sp/800-207/final)

---

## 10. Appendices

### A. Okta Configuration (Example)

```yaml
# Okta App Integration
name: "Company SPA"
type: "Single Page App"
redirect_uris:
  - "https://app.company.com/callback"
  - "https://app.company.com/silent"
post_logout_uris:
  - "https://app.company.com/"
grant_types:
  - "authorization_code"
  - "refresh_token"
response_types:
  - "code"
token_endpoint_auth_method: "none"  # PKCE only
require_pkce: true
```

### B. API Gateway Policy (Example - Pseudocode)

```
policy validate_token:
  1. Extract Authorization header
  2. Verify Bearer token format
  3. Decode JWT (without validation)
  4. Fetch Okta public key (cached)
  5. Validate JWT signature
  6. Check exp claim (must be > now)
  7. Check aud claim (must match API)
  8. Check device_id claim (must be in device registry)
  9. Rate limit: 100 req/min per user
  10. Log request (user, device, ip, resource)
  11. Allow/Deny based on RBAC
```

### C. Sample Error Responses

```json
{
  "error": "invalid_token",
  "error_description": "Token expired",
  "error_uri": "https://docs.company.com/errors/invalid-token"
}
```

---

**Status**: Ready for Security Review  
**Next Step**: Submit threat model & security checklist for review

