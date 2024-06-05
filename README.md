# patch
A simple communication backend based on patchbay.pub's ideas with authentication
## Design
### Authentication
Authentication can be optional if anonymous access is allowed, but might still be needed in some special cases.
Authentication is done using either oAuth2 via Github or using a github personal access token.
If using oAuth2 login, team memberships are synchronized every hour but can be rotated by renewing the session cookie or by the instance admin incrementing the cookie version.
If using personal access token authentication the token should only be used to acquire a cookie as requests using personal access tokens directly are heavily rate limited. Team memberships are synchronized during cookie creation or renewal.

### Data Model
As in patchbay.pub there are different modes of operation, but all focus on receiving information and forwarding it to another consumer.
Available modes:
- pubsub - In pubsub mode a received POST request is distributed to all listening consumers. If ?at-least-once the producer blocks until at least one consumer received the message
- fifo - In fifo mode each received POST request it matched to one consumer and blocks until a consumer GETs the resource.
- req/res - In request-reponse mode requests sent to /req/$path can be answered by a request sending a request to /res/$path
            There's also a double clutch mode to gain more control over the requests as described in https://patchbay.pub/docs/index.html
