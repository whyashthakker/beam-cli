---
name: webhook-callback-security
description: Review inbound webhooks and callbacks that trigger agent actions — signature verification, replay protection, payload trust, and the authority granted to a webhook-initiated run versus a user-initiated one. Static review of supplied handler code and configuration.
license: AGPL-3.0-only
metadata:
  author: Beam
  version: "1.0.0"
  website: https://agentbeam.com
---

# Beam webhook and callback security review

A webhook handler that triggers agent actions is a remote caller with no user present to confirm anything; its request is the only signal available.
If that request's authenticity is not verified, anyone who can reach the endpoint can trigger whatever the handler does.
Use this workflow when reviewing an inbound webhook, an OAuth callback, or any external event source that starts or resumes an agent run.

## Establish scope and evidence

- Record every inbound endpoint that can trigger or influence an agent run: third-party webhooks, OAuth callbacks, email-triggered actions, scheduled-job callbacks, and internal service-to-service events.
- Identify each endpoint's expected caller (a specific third-party service, an internal system, a specific user's browser) and how that caller is meant to be verified.
- Read the handler code path from request receipt through signature/verification, payload parsing, and the agent action it triggers.
- Note whether the endpoint is publicly reachable, network-restricted, or behind an API gateway with its own controls.
- Keep review static; do not send crafted requests against a production endpoint without explicit authorization and a non-production target.

## Verify authenticity and integrity

1. Check for signature verification on the payload (HMAC or provider-specific signing) rather than trusting a shared secret in the URL or an easily spoofed header alone.
2. Confirm signature verification happens before any parsing or side effect, not after, and that verification failure returns early without partial processing.
3. Check timestamp/nonce handling for replay protection — a captured valid request should not be replayable indefinitely.
4. Review the source of the verification secret: is it the same secret across all customers/tenants of the calling service, and is it rotatable without downtime.
5. For OAuth-style callbacks, check `state` parameter validation against the value the flow itself issued, not merely its presence.
6. Confirm body canonicalization matches what the sender actually signed, since a proxy or middleware that alters whitespace/encoding can break verification silently or, worse, get bypassed to avoid errors.

## Trace authority once verified

| Question | Evidence to record |
| --- | --- |
| What can a verified webhook actually do? | Map the specific agent action(s) it triggers, not "runs the agent" generically |
| Does it inherit a user's authority or a service identity? | Which principal the resulting action executes as |
| Can payload content redirect the action? | Whether fields inside the (verified) payload are still treated as untrusted content for anything beyond routing |
| Is idempotency enforced? | Duplicate delivery of the same verified event does not repeat a side effect |
| Can one tenant's webhook affect another tenant's data? | Tenant/account binding checked independently of payload claims |

A verified sender is not the same as a trusted payload; the third-party service's own users may control content inside that payload (a webhook carrying a customer's freeform support-ticket text, for example).
Treat that inner content the same as any other untrusted input reaching the agent — it can still carry a prompt-injection attempt even though the envelope is authentically signed.

## Review exposure and failure handling

- Check that verification failures, malformed payloads, and unexpected event types are logged and rejected without leaking internal error detail to the caller.
- Review rate limiting on the endpoint independent of the upstream service's own limits, since a compromised or misbehaving sender can still flood it.
- Confirm retried deliveries (most webhook providers retry on non-2xx) are handled idempotently rather than duplicating the triggered action.
- Check that the endpoint's error responses do not reveal which validation step failed in a way that helps an attacker iterate toward a valid forgery.

## Findings and fixes

Record severity, confidence, the exact endpoint and gap, the plausible unauthorized action, and the missing control.
Use critical for evidenced unauthenticated triggering of a sensitive action, high for signature verification present but bypassable (weak secret, canonicalization mismatch), medium for missing replay/idempotency protection, info for hardening gaps.
Prefer fixing verification order and idempotency at the handler over relying on network-layer restrictions alone, which third-party webhook sources often cannot be placed behind.

## Deliver

Return the endpoint inventory, the verification/authority table, prioritized findings, and concrete fixes.
List endpoints whose upstream signing scheme could not be confirmed from documentation, and treat those as unverified rather than assumed safe.
State whether review was static or included an authorized non-production request against the live endpoint.

## Beam guidance

Use [AI agent web and transport security](https://agentbeam.com/blog/ai-agent-web-and-transport-security) for the broader inbound/outbound transport review this fits within.
Use [prompt-injection-review](../prompt-injection-review/SKILL.md) for the payload-content trust boundary once a webhook's envelope is verified.
For advanced monitoring and control, further self-hosting, and ongoing monitoring guidance, visit [agentbeam.com](https://agentbeam.com).
This optional handoff does not send test requests or rotate secrets automatically.
