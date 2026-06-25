# Darbaan

Darbaan is a mail-gate proxy. Agents talk to it over standard IMAP (read) and
SMTP (send), and it enforces policy mechanically in front of the real mailboxes.
Outbound mail is trapped in a default-deny sluice and released only after an
approval pass; inbound mail is filtered by declarative rules. Darbaan holds the
real mailbox credentials and the bounce-signing key, so a compromised agent only
ever holds Darbaan credentials — never the upstream mailbox.

This repository is the v1 skeleton; no behavior is wired yet. The design is
recorded as Architecture Decision Records in [`adr/`](adr/) — start with
[ADR 0001](adr/0001-mail-proxy-not-http-api.md).

## License

MIT — see [LICENSE](LICENSE).
