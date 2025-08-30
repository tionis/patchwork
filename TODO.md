# TODOs
- [ ] fix tests
      don't use test.forgejo.dev, mock the server instead
      there might be some failures related to the new "public" token that is used when none is specified in a user namespace
- [ ] add a prometheus export endpoint
  - [ ] check if implementation works and write tests for it
  - [ ] the endpoint should export enough data to see problems and detect abuse (e.g. one user sending too many requests)
  - [ ] make sure the endpoint is secured
- [ ] add rate limiting for public namespaces
  - [ ] check if implementation works and write tests for it
- [ ] clean up code, making it more readable using clean abstractions and comments where necessary