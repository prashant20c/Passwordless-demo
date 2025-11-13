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
      "public_key": "BASE64_ED25519_PUBLIC_KEY"
    }
  ],
  "logins": [
    {
      "id": 1,
      "login_id": "pending123",
      "user_id": 1,
      "challenge": "BASE64_CHALLENGE",
      "status": "PENDING",
      "created_at": "2025-11-12T10:00:00+00:00"
    },
    {
      "id": 2,
      "login_id": "rejected123",
      "user_id": 1,
      "challenge": "BASE64_CHALLENGE",
      "status": "REJECTED",
      "created_at": "2025-11-12T09:50:00+00:00",
      "rejected_at": "2025-11-12T09:51:00+00:00",
      "device_id": 1
    },
    {
      "id": 3,
      "login_id": "ended123",
      "user_id": 1,
      "challenge": "BASE64_CHALLENGE",
      "status": "ENDED",
      "created_at": "2025-11-12T09:00:00+00:00",
      "approved_at": "2025-11-12T09:01:00+00:00",
      "ended_at": "2025-11-12T11:00:00+00:00",
      "device_id": 1
    }
  ]
}
```

## Notes

- To simulate an in-progress link flow, you can set `link_code` to a 6-digit string (for example `"483921"`) and `link_code_expires_at` to an ISO timestamp 10 minutes in the future. Remember to reset both fields to `null` after the device links successfully.
- After linking a device using the Python GUI, copy the generated `public_key` from `device-gui/state.json` into the `devices` array if you want to seed the mock database.
