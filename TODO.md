- [ ] remove is_admin from auth config, only rely on namespacing patterns
- [ ] add instruction to .vscode/copilot-instructions.md to always updated the documentation in docs/, static/index.html and README.md
- [ ] remove ntfy endpoint, I will use php based serverless functions instead
- [ ] rework gh CI to test on all branches, but build and push only on main
- [ ] migrate away from forgejo based backend to some externally managed on
      the main idea being that some external service (a php script) managed tokens instead
      either by being a CA that gives users JWTs, or by minting tokens and offering a token validation endpoint to check if they are valid.
      If we use the CA, then the server should fetch/subscribe to a revocation list (or it is pushed out), if we use the token validation endpoint we should cache the result, with a webhook based (or other streaming based) token invalidation
- [ ] add data from mqtt broker to prometheus data
