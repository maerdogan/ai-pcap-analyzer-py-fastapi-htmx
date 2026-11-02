# REST API

Create a token under **Preferences**. It is shown once. Send it with each call:

```bash
curl -H "Authorization: Bearer $TOKEN" https://pcap.example.internal/api/v1/analyses
```

| Call | Result |
|---|---|
| `POST /api/v1/captures` | Upload with the form field `capture`. Optional: `keylog`, `rsa_key`, `host_a`, `host_b`, `port`, `display_filter`. Returns `202` and a `job`. |
| `GET /api/v1/jobs/{job}` | `state` is `waiting`, `running`, `done`, `failed` or `cancelled`. `analysis` holds the id when done. |
| `GET /api/v1/analyses` | Saved analyses. |
| `GET /api/v1/analyses/{id}` | Details of one analysis. |
| `GET /api/v1/analyses/{id}/{section}` | `overview`, `urls`, `connections`, `hosts`, `issues` or `slowest`. |
| `DELETE /api/v1/analyses/{id}` | Deletes an analysis. |

Upload and wait:

```bash
job=$(curl -s -H "Authorization: Bearer $TOKEN" -F capture=@web.pcap "$URL/api/v1/captures" | python3 -c 'import json,sys; print(json.load(sys.stdin)["job"])')
curl -s -H "Authorization: Bearer $TOKEN" "$URL/api/v1/jobs/$job"
```

Errors come back as `{"error": "..."}`. A wrong or revoked token gives `401`. A token can do everything the web login can, apart from managing tokens, so keep it like a password.
