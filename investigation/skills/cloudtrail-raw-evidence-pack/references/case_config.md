# Raw Evidence Case Config

`case-config.json` shape:

```json
{
  "cases": [
    {
      "id": "01_example",
      "title": "Example case",
      "match": {
        "eventName": ["CreateAccessKey"],
        "actor": ["ExampleRole"],
        "sourceIPAddress": ["203.0.113.10"],
        "accountId": ["123456789012"]
      }
    }
  ]
}
```

Supported match keys:

- CloudTrail top-level keys such as `eventName`, `eventSource`, `sourceIPAddress`, `awsRegion`, `recipientAccountId`
- `actor`, derived from user identity/session issuer
- `accountId`, derived from `userIdentity.accountId` or `recipientAccountId`

Match values are ORed within a key and ANDed across keys. If no case config is supplied, all records go into `all_events`.
