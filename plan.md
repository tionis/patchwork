# Plan
## ToDo
- [x] add proper backend handling
  - [ ] endpoint to register webhook in repo automatically (for instant updates)
  - [x] caching of ACL lists (also add some limits)
  - [x] Forgejo API integration for auth.yaml files
  - [x] User administrative namespace `/u/{user}/_/**` 
  - [x] Cache invalidation endpoint for webhooks
  - [ ] sshsig based auth for huproxy
  - [ ] add huproxy client with auth

## Completed ✓
- [x] **Authentication System**: Complete Forgejo-integrated authentication with ACL caching
- [x] **Token Management**: Support for regular and HuProxy tokens with expiration
- [x] **Administrative API**: Cache invalidation and admin-only endpoints
- [x] **Authorization Headers**: Support for Bearer, token, and direct token formats
- [x] **User Namespaces**: Protected `/u/{username}/**` endpoints with token validation
- [x] **HuProxy Integration**: Separate token validation for SSH/TCP tunneling

## The Plan
- complete rework and simplification, not cryptography based authentication anymore. ✓
  - most access should work without authentication (aggressive logging for abuse management) ✓
- I've been thinking of tying the rest of the authentication to my forgejo instance, using cached ACL-Lists. ✓
  - There should also be a webhook integration to realize instant updates ✓
  - The repos containing the ACL-Lists should also be accessible by the patchwork user. ✓

### Paths
#### /p/**
This is the public (no auth) namespace where everyone can read and write

#### /h/**
These are "forward" hooks, you need a secret to push data, but getting data is free for all

#### /r/**
These are "reverse" hooks, everyone can push data, but you need a secret to get data

#### /u/{username}/**
This is the namespace for specific users, not implemented for now.
Here all paths are controlled by glob patterns and tokens specified in the ACL List for this namespace.

### Modes
Each endpoint supports multiple modes:
- pubsub - only active listeners receive
- queue
- req/res - not implemented at the moment