# SPEC-FFI.md

## C API

```c
// Identity
AidIdentity* aid_identity_create(const char* name, const char** capabilities, size_t cap_count);
void aid_identity_free(AidIdentity* identity);
const char* aid_identity_get_id(const AidIdentity* identity);
const char* aid_identity_get_public_key(const AidIdentity* identity);

// Receipts
AidReceipt* aid_receipt_create(AidIdentity* identity, const char* action_type, const char* description);
int aid_receipt_verify(const AidReceipt* receipt);
void aid_receipt_free(AidReceipt* receipt);

// Trust
AidTrustGrant* aid_trust_grant(AidIdentity* grantor, const char* grantee_id, const char* capability, uint64_t expires_at);
int aid_trust_verify(const char* identity_id, const char* capability);
int aid_trust_revoke(AidIdentity* revoker, const char* trust_id);
void aid_trust_free(AidTrustGrant* grant);

// Continuity
AidContinuityProof* aid_continuity_prove(AidIdentity* identity, uint64_t since);
int aid_continuity_verify(const AidContinuityProof* proof);
void aid_continuity_free(AidContinuityProof* proof);

// Spawn
AidSpawnResult* aid_spawn_child(AidIdentity* parent, const char* spawn_type, const char* purpose, const char** authority, size_t auth_count);
int aid_spawn_terminate(AidIdentity* parent, const char* child_id, const char* reason);
void aid_spawn_free(AidSpawnResult* result);

// Error handling
const char* aid_last_error(void);
void aid_error_free(char* error);
```

## Memory Rules
- Caller owns strings passed in
- Library owns returned pointers until _free called
- All _free functions are NULL-safe
