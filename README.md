# Patchwork

A simple communication backend for scripts and other small applications.

## Usage

Patchworks data model is based on
[Patchbay.pub\'s](https://patchbay.pub) approach. The service provides a
nearly unlimited amount of virtual \"channels\" represented by a path.
Data POSTed to a channel can be received by clients doing GET requests,
the exact behaviour depends on the type (specified with the \"type\"
query parameter). The Mime content-type can also be specified with the
\"mime\" query parameter.

The available types are:

-   **fifo/queue**: Each message is received by exactly one receiver, if
    no listeners are active the server blocks until there is one. This
    is the default mode.
-   **pubsub**: All receivers receive the published message, if no
    listeners are active the server returns \"HTTP 204 NO CONTENT\".
-   **blockpub/blocksub**: Same behaviour as pubsub, but the server
    blocks until there is at least one listener.

## Authentication and Authorization

The server is partionend by namespaces. Each namespace has different
rules for auth:

-   **/p/\*\***: No authentication required.
-   **/u/{github_user}/\*\***: Token has to be signed by a ssh key of
    the github user.
-   **/k/{key_fingerprint}/\*\***: Token has to be signed by the ssh key
    with the given fingerprint.
-   **/w/{webcrypto_fingerprint}/\*\***: Token has to be signed by the
    webcrypto key with the given fingerprint.
-   **/g/{gist_id}/\*\***: Token has to be signed by an allowed signer
    loaded from the gist

## Token Format

Tokens are base64-encoded, gzipped json objects with two keys:
\"signature\" and \"data\". The \"signature\" is an openssh signature of
the \"data\". The \"data\" key is a json object with the following keys:

        {
        "AllowedWritePaths": ["/some-path/*", "!/some-path/forbidden/*"],
        "AllowedReadPaths": [],
        "ValidBefore": -1,
        "ValidAfter": -1,
        }
      

AllowedWritePaths and AllowedReadPaths are OpenSSH style pattern lists
(essentially a list of globs), while the ValidBefore and ValidAfter
fields specify a unix time after/before which the token is invalid. If
it\'s -1, there is no expiry.

## Tools

You can download a bash based client [here](/patchwork.sh).
