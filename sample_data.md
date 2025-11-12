# Sample data for JSON Server (copy into mock-api/db.json)

```
{
  "users": [
    {
      "id": 1,
      "full_name": "Alice Shopper",
      "email": "alice@example.com",
      "password_hash": "$2y$10$REPLACE_WITH_REAL_HASH"
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
  "logins": []
}
```

## Notes

- Replace `REPLACE_WITH_REAL_HASH` using `php -r "echo password_hash('your_password', PASSWORD_DEFAULT);"` and paste the output into `password_hash`.
- After linking a device using the Python GUI, copy the generated `public_key` from `device-gui/state.json` into the `devices` array if you want to seed the mock database.
