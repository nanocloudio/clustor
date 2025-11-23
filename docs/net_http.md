# Manual HTTP Parser Limitations

Clustor ships a very small HTTP/1.1 implementation that is just large enough for
our control-plane and diagnostics endpoints. The parser intentionally omits a
number of features to keep the code simple and auditable:

- Only requests with an explicit `Content-Length` header are accepted. Chunked
  transfer encoding and streaming bodies are rejected with
  `HttpError::ChunkedEncodingUnsupported`.
- Header names and values must be ASCII and the total header section is capped
  at 64 KiB. Larger payloads result in `HttpError::HeadersTooLarge`.
- Request bodies are buffered eagerly and limited to 4 MiB per request. Clients
  attempting to send more data receive `HttpError::BodyTooLarge`.
- The parser does not implement HTTP keep-alive negotiation; every response
  ends with `Connection: close` and the client is expected to reconnect.
- Timeouts are enforced by `RequestDeadline` and socket-level read/write timeouts
  inside each server. When a deadline expires the connection is closed with a
  `408 Request Timeout` response.

These constraints keep the networking surface area extremely small. The manual
parser should only be used for trusted systems inside the cluster perimeter and
is not a general-purpose HTTP framework.
