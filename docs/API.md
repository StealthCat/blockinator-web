# Resolver integration and decision API

[Back to README](../README.md)

Run Blockinator alongside a DNS server. The resolver plugin enforces the response; Blockinator is an HTTP policy service.

## Technitium integration

The [companion Technitium DNS application](https://github.com/StealthCat/blockinator-technitium) can call Blockinator for every DNS request.

Example:

```json
{
  "endpoint": "http://192.168.1.50:8080/api/v1/decision",
  "apiKey": "one-enabled-blockinator-api-key",
  "serverId": "technitium-1",
  "timeoutMs": 250,
  "failMode": "open"
}
```

When HTTPS is enabled, use the configured HTTPS hostname/port instead.

If Technitium and Blockinator share a Docker network and you intentionally want to bypass Caddy:

```json
{
  "endpoint": "http://blockinator:8080/api/v1/decision"
}
```

## Decision API

### Authentication check

```text
GET /api/v1/ping
X-Api-Key: <enabled Blockinator API key>
```

Example:

```bash
curl -i \
  -H 'X-Api-Key: YOUR_KEY' \
  http://DOCKER-HOST:8080/api/v1/ping
```

### Policy decision

```text
POST /api/v1/decision
X-Api-Key: <enabled Blockinator API key>
Content-Type: application/json
```

Example request:

```json
{
  "server_id": "technitium-1",
  "protocol": "Udp",
  "client": {
    "ip": "192.168.20.44",
    "port": 53012
  },
  "dns": {
    "identifier": 1234,
    "is_response": false,
    "opcode": "StandardQuery",
    "recursion_desired": true,
    "rcode": "NoError",
    "has_edns": true,
    "question_count": 1,
    "wire_base64": "EjQBAAABAAAAAAAB...",
    "questions": [
      {
        "name": "ads.example.com",
        "type": "A",
        "class": "IN"
      }
    ]
  }
}
```

Example blocked response:

```json
{
  "block": true,
  "reason": "blocklist_match",
  "matched_scope": "Guest Wi-Fi",
  "matched_list": "Advertising",
  "matched_list_type": "block",
  "matched_domain": "ads.example.com",
  "response_mode": "nxdomain"
}
```

The API validates client IP addresses, port ranges, DNS label/name lengths and accepts 1–16 questions per request. Policy request bodies are limited to 256 KiB and `wire_base64` to 87,380 characters. Invalid payloads return HTTP 422; oversized bodies return HTTP 413.

When multiple DNS questions are supplied, Blockinator evaluates them in order and returns the first blocking decision. If none block, the first allow decision is returned.

Questions using types selected under **System Settings → Ignored records** are skipped individually; other questions still receive normal policy evaluation. Only when all questions are ignored does Blockinator short-circuit before PTR observation or policy evaluation. It returns an immediate allow decision with reason `ignored_record_type`; the request is not added to Query Log and does not contribute a response-time sample.

For liveness, readiness, and administrator-only runtime diagnostics, see [monitoring](OPERATIONS.md#operational-protections-and-monitoring). Configure HTTPS using the [TLS guide](OPERATIONS.md#https-and-tls).
