# SPEC-CLI.md

## Commands

```
aid init [--name NAME] [--ceiling CAPS]     Create new identity
aid show [ID]                                Show identity details
aid list                                     List all identities
aid export [ID] [--output FILE]              Export public identity
aid import FILE                              Import identity

aid sign --action TYPE --description DESC    Sign action, create receipt
aid verify receipt RECEIPT_ID                Verify receipt
aid verify chain [--identity ID]             Verify receipt chain

aid trust grant --to ID --capability CAP [--expires DURATION]
aid trust revoke TRUST_ID [--cascade]
aid trust list [--granted|--received]
aid trust verify --identity ID --capability CAP

aid spawn --type TYPE --purpose DESC --authority CAPS [--lifetime DURATION]
aid spawn list [--active|--terminated]
aid spawn terminate CHILD_ID --reason REASON
aid spawn lineage [ID]

aid continuity prove [--since TIMESTAMP] [--type full|anchor|sample]
aid continuity verify CLAIM_ID
aid continuity status
aid heartbeat [--interval SECONDS]

aid rotate [--reason REASON]
```

## Output Formats
- `--format text` (default): Human-readable
- `--format json`: JSON output
- `--format quiet`: Minimal output (IDs only)

## Exit Codes
- 0: Success
- 1: General error
- 2: Invalid arguments
- 3: Identity not found
- 4: Verification failed
- 5: Permission denied
