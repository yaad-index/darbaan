# ADR 0040: Telemetry exports counts, never mail

**Status:** Proposed (2026-10-06)

## Context

Darbaan holds mail it must not leak: addresses, names, subjects, bodies, message
ids, and the recipients' hosts. ADR 0002 keeps credentials in the trusted box,
ADR 0011 keeps an append-only audit log of what happened to each message, and the
admin API's scopes (ADR 0029) decide who may read held content. All of these are
inside Darbaan.

An operator wants to see how a running Darbaan is doing without opening the audit
log or the queue: how many messages wait for a decision, how many were approved,
rejected or sent, how long a send takes, and whether the upstream SMTP and IMAP
connections are failing. OpenTelemetry metrics answer that, sent over OTLP to a
collector the operator runs.

A collector is outside Darbaan. Nothing there is covered by the admin scopes, the
audit log's retention or the content store's access rules, and it keeps data for
as long as it is configured to. So anything exported must be safe to keep outside
Darbaan indefinitely.

Traces are riskier than metrics here. The standard HTTP instrumentation puts each
request's full URL on its span. The admin API carries message and hold ids in its
paths (`/queue/{id}/approve`, `/holds/{id}/content`), and the Telegram Bot API
carries the bot token in its URL path. Traced as the libraries trace by default,
every approval would export a message id, and every Telegram call would export a
credential.

## Decision

1. **Export only when an endpoint is set.** Darbaan sends telemetry only when the
   standard `OTEL_EXPORTER_OTLP_*` environment variables name an endpoint. With
   none set, nothing leaves the process. The resource is `service.name=darbaan`
   and `service.version` from the build; the operator may add resource attributes
   through `OTEL_RESOURCE_ATTRIBUTES`, for example to tell two deployments apart.
2. **Metrics only, no traces.** Darbaan exports metrics and no spans. A later ADR
   may add traces, and must say how no URL path, id or credential reaches a span.
3. **No mail, ever.** No metric attribute value, metric name or resource attribute
   set by Darbaan carries an email address, a display name, a subject, a body or
   any part of one, a message id, a hold id, a recipient's or sender's host or
   domain, a label, a filter rule's text, an error message, or any other text from
   mail or from a remote server.
4. **Attributes take values from fixed sets in the code.** Every attribute value is
   one of a closed set defined in Darbaan's source: an outcome, a direction, an
   error kind, a protocol command name, an HTTP method or status code, a route
   template. A value read from configuration or from a message is not an attribute,
   so neither an inbox name, an agent's login, an admin client's name nor an
   operator's identity labels a metric. Counts are per process; the operator tells
   deployments apart with resource attributes (1).
5. **Error kinds, not errors.** A failure is counted by kind (for example
   `permanent`, `transient`, `dial`, `auth`, `tls`, `timeout`, `protocol`,
   `other`), classified in code. An SMTP reply counts by its class (`4xx`, `5xx`),
   never by its text or extended code.
6. **HTTP metrics follow the semantic conventions without the URL.** The admin API
   and Darbaan's own HTTP clients record the conventions' HTTP server and client
   duration metrics with method, status code, and for the server the route
   template (`/queue/{id}`), never the path. Client metrics keep the server address
   only for an endpoint Darbaan is configured to call, never an address taken from
   mail.
7. **Names.** A metric takes the OpenTelemetry semantic conventions' name where
   one exists, else `darbaan.<area>.<thing>`. Its unit goes in the unit field. The
   README lists every metric with its unit and attributes.

## Consequences

- An operator can see queue depth, decisions, send latency and upstream failures,
  and alert on them, without any access to mail.
- Which message, inbox or agent a number is about is not in telemetry. Finding it
  means the audit log or the admin API, under their scopes.
- Per-inbox numbers are not available, even though inbox names come from the
  operator's own configuration: inbox names are often addresses or people's names,
  and point 4 keeps every attribute free of configured text. A deployment with
  several inboxes sees their totals.
- Without traces, a slow approval cannot be followed across the admin API, the
  approval chain and the send in one view. Adding that takes a new ADR (point 2).
- A new metric or attribute is reviewed against points 3 and 4. A value that is not
  in a closed set in the code does not become an attribute.
