# Sample data for JSON Server (copy into mock-api/db.json)

```
{
  "users": [
    {
      "id": 1,
      "full_name": "Alice Shopper",
      "email": "alice@example.com",
      "link_code": null,
      "link_code_expires_at": null
    }
  ],
  "devices": [
    {
      "id": 1,
      "user_id": 1,
      "device_name": "Alice Laptop",
      "public_key": "BASE64_ED25519_PUBLIC_KEY",
      "linked_at": "2025-11-12T09:45:00+00:00"
    }
  ],
  "logins": [
    {
      "id": 1,
      "login_id": "pending123",
      "session_id": "pending123",
      "user_id": 1,
      "challenge": "BASE64_CHALLENGE",
      "status": "PENDING",
      "created_at": "2025-11-12T10:00:00+00:00",
      "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
      "ip_address": "203.0.113.10",
      "client_label": "Safari on macOS"
    },
    {
      "id": 2,
      "login_id": "rejected123",
      "session_id": "rejected123",
      "user_id": 1,
      "challenge": "BASE64_CHALLENGE",
      "status": "REJECTED",
      "created_at": "2025-11-12T09:50:00+00:00",
      "rejected_at": "2025-11-12T09:51:00+00:00",
      "device_id": 1,
      "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
      "ip_address": "203.0.113.24",
      "client_label": "Mobile Safari on iOS"
    },
    {
      "id": 3,
      "login_id": "ended123",
      "session_id": "ended123",
      "user_id": 1,
      "challenge": "BASE64_CHALLENGE",
      "status": "ENDED",
      "created_at": "2025-11-12T09:00:00+00:00",
      "approved_at": "2025-11-12T09:01:00+00:00",
      "ended_at": "2025-11-12T11:00:00+00:00",
      "device_id": 1,
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "ip_address": "198.51.100.14",
      "client_label": "Chrome on Windows"
    }
  ],
  "sessions": [
    {
      "id": 1,
      "session_id": "ended123",
      "login_id": "ended123",
      "user_id": 1,
      "device_id": 1,
      "client_label": "Chrome on Windows",
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "ip_address": "198.51.100.14",
      "status": "active",
      "created_at": "2025-11-12T09:00:00+00:00",
      "last_seen_at": "2025-11-12T11:00:00+00:00",
      "revoked_at": null
    }
  ]
}
```

## Notes

- To simulate an in-progress link flow, you can set `link_code` to a 6-digit string (for example `"483921"`) and `link_code_expires_at` to an ISO timestamp 10 minutes in the future. Remember to reset both fields to `null` after the device links successfully.
- After linking a device using the Python GUI, copy the generated `public_key` from `device-gui/state.json` into the `devices` array if you want to seed the mock database.
- The `sessions` collection powers both the device console and the web dashboard. Every approved login should set the `session_id` on the `logins` record and create/update the corresponding session document with metadata like `client_label`, `ip_address`, and timestamps.
