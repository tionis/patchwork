# Plan
- complete rework and simplification, not cryptography based authentication anymore.
  - most access should work without authentication (aggressive logging for abuse management)
- I've been thinking of tying the rest of the authentication to my forgejo instance, using cached ACL-Lists.
  - There should also be a webhook integration to realize instant updates
  - The repos containing the ACL-Lists should also be accessible by the patchwork user.

## Paths
### /p/**
This is the public (no auth) namespace where everyone can read and write

### /h/**
These are "forward" hooks, you need a secret to push data, but getting data is free for all

### /r/**
These are "reverse" hooks, everyone can push data, but you need a secret to get data

### /u/{username}/**
This is the namespace for specific users, not implemented for now.
Here all paths are controlled by glob patterns and tokens specified in the ACL List for this namespace.

## Modes
Each endpoint supports multiple modes:
- pubsub - only active listeners receive
- queue
- req/res - not implemented at the moment