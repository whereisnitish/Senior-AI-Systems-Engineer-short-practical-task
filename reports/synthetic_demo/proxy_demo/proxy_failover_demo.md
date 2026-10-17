# Proxy health and controlled failover - SIMULATED

Generated 2026-10-17T05:47:08.021958+00:00 | correlation id `proxy-demo-de6a8a18460a4b69` | credential leak check: **passed**

> Proxies and the neutral endpoint are local stand-ins on 127.0.0.1 (app/simulation/local_network.py).
> No company-approved proxy was available; this is not a test of real proxies.
> Credentials were synthetic, generated for this run, resolved from the dev-only vault and never logged.

| # | Scene | Expected | Outcome | Decision / attempts |
|---|---|---|---|---|
| 1 | 1. Health check all approved proxies | a and b healthy; c rejects its credential (407) -> quarantined + maintenance task, no retry | endpoint_reachable |  / local-sim-a: ok/healthy, local-sim-b: ok/healthy, local-sim-c: proxy_failure/quarantined |
| 2 | 2. Acquire session (affinity) | bound to the highest-priority healthy proxy (a) | bound |  |
| 3 | 3. Request via session | proxy a healthy -> connection preserved | ok | Proxy healthy: connection preserved (session affinity). / attempts: none(23.3ms) |
| 4 | 4. Proxy a goes down | 3 bounded attempts with backoff, then controlled failover to b after b passes a health check | failover | Controlled failover local-sim-a -> local-sim-b: proxy_connect_timeout after 3 attempt(s). Candidate health-checked before the session moved. / attempts: proxy_connect_timeout(1015.0ms), proxy_connect_timeout(1003.8ms), proxy_connect_timeout(1005.3ms) |
| 5 | 5a. Proxy a recovers | a passes a fresh health check | ok |  / attempts: none(13.0ms) |
| 6 | 5b. Request via session again | session stays on b - no flapping back once a recovers | ok | Proxy healthy: connection preserved (session affinity). / attempts: none(4.6ms) |
| 7 | 6. Endpoint returns 503 | endpoint failure, not proxy failure -> proxy preserved, no failover | endpoint_failure | The endpoint is failing (the proxy relayed an error). Proxy preserved: failover would not help. / attempts: endpoint_error(4.8ms), endpoint_error(4.8ms), endpoint_error(4.8ms) |
| 8 | 7. Endpoint rate-limits (429) | back off on the SAME proxy; rotating to escape a rate limit is refused | rate_limited | Rate limited: backing off on the SAME proxy. Rotating proxies to escape a rate limit is not allowed. / attempts: rate_limited(4.7ms) |
| 9 | 7b. Attempt rotation during back-off | refused | rotation_refused | session is in rate-limit back-off; rotating now would be evasion, so it is refused |
| 10 | 8. Endpoint presents a security challenge | session PAUSED + human review task; no retry, no rotation | paused_security_review | Security challenge: session PAUSED for human review. No retry and no proxy rotation - rotating to get past a challenge would be evasion. / attempts: security_challenge(5.0ms) |
| 11 | 8b. Further traffic while paused | refused until a human reviews | request_refused_while_paused | Session is paused pending human review (security challenge returned by the test endpoint); no traffic is sent until reviewed |

## Redacted transition log (excerpt)

```json
{"ts": "2026-10-17T05:47:03.538+00:00", "event": "proxy.session_decision", "outcome": "ok", "proxy_id": "local-sim-a", "from_proxy": null, "to_proxy": null, "reason": null, "retry_count": null, "decision": "Proxy healthy: connection preserved (session affinity)."}
{"ts": "2026-10-17T05:47:07.453+00:00", "event": "proxy.failover", "outcome": "rebound", "proxy_id": null, "from_proxy": "local-sim-a", "to_proxy": "local-sim-b", "reason": "proxy_connect_timeout after 3 attempt(s)", "retry_count": 2, "decision": null}
{"ts": "2026-10-17T05:47:07.468+00:00", "event": "proxy.session_decision", "outcome": "failover", "proxy_id": "local-sim-b", "from_proxy": null, "to_proxy": null, "reason": null, "retry_count": null, "decision": "Controlled failover local-sim-a -> local-sim-b: proxy_connect_timeout after 3 attempt(s). Candidate health-checked before the session moved."}
{"ts": "2026-10-17T05:47:07.500+00:00", "event": "proxy.session_decision", "outcome": "ok", "proxy_id": "local-sim-b", "from_proxy": null, "to_proxy": null, "reason": null, "retry_count": null, "decision": "Proxy healthy: connection preserved (session affinity)."}
{"ts": "2026-10-17T05:47:07.944+00:00", "event": "proxy.session_decision", "outcome": "endpoint_failure", "proxy_id": "local-sim-b", "from_proxy": null, "to_proxy": null, "reason": null, "retry_count": null, "decision": "The endpoint is failing (the proxy relayed an error). Proxy preserved: failover would not help."}
{"ts": "2026-10-17T05:47:07.960+00:00", "event": "proxy.session_decision", "outcome": "rate_limited", "proxy_id": "local-sim-b", "from_proxy": null, "to_proxy": null, "reason": null, "retry_count": null, "decision": "Rate limited: backing off on the SAME proxy. Rotating proxies to escape a rate limit is not allowed."}
{"ts": "2026-10-17T05:47:07.991+00:00", "event": "proxy.session_paused", "outcome": "paused_security_review", "proxy_id": null, "from_proxy": null, "to_proxy": null, "reason": "security challenge returned by the test endpoint", "retry_count": null, "decision": null}
{"ts": "2026-10-17T05:47:07.991+00:00", "event": "proxy.session_decision", "outcome": "paused_security_review", "proxy_id": "local-sim-a", "from_proxy": null, "to_proxy": null, "reason": null, "retry_count": null, "decision": "Security challenge: session PAUSED for human review. No retry and no proxy rotation - rotating to get past a challenge would be evasion."}
```
