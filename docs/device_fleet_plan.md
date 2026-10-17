# Device fleet automation (optional Part D) – not implemented; deployment plan

**Status:** skipped deliberately. The time went to the weighted areas (reliability, secrets, handoffs,
proxies). The fleet would only ever run a **neutral sample test app, never Instagram or any social app**. That
rule would be enforced by an allowlist of package names checked before every job and audited on every device.

## How the existing code would extend

The fleet would reuse the durable task model already in this repository. Each job is a row with step-level
completion records. The device worker leases a job, records each completed step, and on reconnect resumes
from the first incomplete step (keyed by job id and step id). Device health checks run before every lease
and after every step:

- `adb get-state`
- battery level and temperature (`dumpsys battery`)
- free storage (`df /data`)
- network (`dumpsys connectivity` and a ping to an internal endpoint)

Every run saves a screenshot (`adb exec-out screencap -p`) and a redacted log. Parallelism comes from one
worker process per device, pulling from the same queue.

## Running 20–50 devices

| Area | Plan |
|---|---|
| Hardware | Mid-range Android phones of one model (simplifies images). One host (small form-factor PC, Linux) per 10–16 devices, on industrial **powered** USB hubs with per-port power switching. Spare devices: 10%. |
| Power | Hubs on a UPS. Charging limited to ~40–80% (charge-control setting or timed port power) to avoid battery swelling; batteries inspected monthly. |
| Cooling | Open wire racks, devices standing with spacing, room kept below ~27 °C. Per-device battery-temperature alerts above ~40 °C pause jobs on that device. |
| OS and app updates | Android Enterprise / MDM in kiosk mode. OS updates pinned and rolled out in waves (1 device → 10% → all) after a smoke-test job. The test app is deployed by MDM or `adb install` from a signed artifact store. Auto-update off. |
| Remote access security | Devices and hosts on an isolated VLAN with no inbound internet. Operators reach hosts only over VPN (WireGuard) with SSO and MFA. ADB never exposed on the network (USB only, per-host ADB keys). Worker credentials come from the vault. Every session and command is logged. |
| Monitoring | Host exporters plus per-device metrics (state, battery, temperature, storage, job success rate) into Prometheus/Grafana or the company equivalent. Alerts on offline > 5 min, temperature, low storage and repeated job failure. Device quarantine is automatic and returns via a human task. |
| Recovery | Disconnect → mark the device unhealthy → requeue the job with step state preserved → port power-cycle via the hub → re-check → resume. Bounded attempts, then a human task. |

## Cost per device per month (ESTIMATES – assumptions stated, not quotes)

| Item | Assumption | Estimate (USD) |
|---|---|---|
| Device | ~$200 mid-range phone amortised over 24 months | ~8 |
| Host and hub share | ~$900 host + hubs per 12 devices, over 36 months | ~2 |
| Power | ~5 W average per device incl. overhead, $0.20/kWh | ~1 |
| MDM licence | Typical per-device SaaS pricing | 2–4 |
| Network | Shared site connectivity apportioned; no SIM data | 1–2 |
| Space and operations labour | 0.1–0.2 FTE for 50 devices, apportioned | 10–25 |
| **Total** | on-premises, 50 devices | **~25–40 per device per month** |

These are planning estimates. Device price, energy cost, labour rates and MDM pricing should be replaced
with real quotes. A managed cloud device farm avoids hardware and space costs but is usually much more
expensive per dedicated device. Compare it against vendor quotes before deciding.
