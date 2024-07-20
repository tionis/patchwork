# Plan
## Features
- patchbay.pub style handling of paths
    - `$base_url/u/:github_username/...` -> auth by github user
    - `$base_url/s/:ssh_fingerprint/...` -> auth by ssh key
    - `$base_url/p/...` -> public access
    - `$github_username.$base_url/...` -> auth by github user
    - `$ssh_fingerprint.$base_url/...` -> auth by ssh key
    - `public.$base_url/...` -> public access
    - `p.$base_url/...` -> public access
    - `pub.$base_url/...` -> public access
- some way to listen host more complex api via patchwork, ideas:
    - sish style using an ssh-tunnel and some custom subdomain or something similar
    - via some api that uses websockets/sse and some json encoded data layer to handle this -> more dynamic
