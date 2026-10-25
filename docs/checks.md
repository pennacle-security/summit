---
title: Check Catalog
description: Every check in summit, with severity, confirmation basis, CWE and impact.
---

# Check Catalog

Every check states its **confirmation basis**. `confirmed` = an observed fact, `likely` = strong evidence, `needs-manual` = a heuristic that needs a human eye, `info` = context only. The label caps severity (`likely` stops at medium, `needs-manual` at low). That column is not decoration - it is the contract.

## Passive checks (no attack traffic)

| Check | Severity | CWE | Confirmation basis |
|---|---|---|---|
| Missing security headers | low | CWE-693 | header absence |
| Cookie flags (Secure / HttpOnly / SameSite) | low | CWE-614 | header parse |
| SQL error / stack-trace disclosure | low | CWE-209 | baseline-diffed signatures |
| Server and tech version disclosure | info | CWE-200 | header parse |
| CORS wildcard with credentials | low | CWE-942 | header parse |
| Email exposure | info | CWE-359 | regex |
| WAF fingerprint | info | CWE-693 | tight vendor signatures |
| CAPTCHA / anti-bot challenge | info | CWE-807 | challenge markers, reported not solved |
| Resource takeover signature | high | CWE-350 | provider unclaimed-resource page on 404 -> `confirmed` |
| Hardcoded secret in client-side code | medium | CWE-798 | vendor pattern + entropy, value redacted -> `likely` (private keys `confirmed`) |
| Security headers grade | info | CWE-693 | deterministic A..F roll-up |
| Cacheable sensitive response | low | CWE-524 | sensitive marker + no Cache-Control -> `needs-manual` |
| Web cache deception surface | low | CWE-441 | cacheable suffix mirrors session page -> `needs-manual` |
| Known CVE in version banner | low | CWE-1104 | offline CVE database range match -> `needs-manual` |
| Known CVE in frontend library | low | CWE-1104 | body signature (jQuery, lodash, WordPress) -> `needs-manual` |

## Active checks

| Check | Severity | CWE | Confirmation basis |
|---|---|---|---|
| SQL injection, error-based | critical | CWE-89 | fresh DB error vs baseline -> `confirmed` |
| SQL injection, boolean-based | medium | CWE-89 | response divergence + baseline match -> `likely` |
| SQL injection, time-based blind | medium | CWE-89 | calibrated delay reproduced on all probes -> `likely` |
| Reflected XSS | high | CWE-79 | canary + raw payload reflection -> `confirmed` |
| DOM XSS candidate (source->sink) | low | CWE-79 | `location.hash` flows into `innerHTML` -> `needs-manual` |
| WAF filter bypass | high | CWE-693 | tampered payload lands decoded -> `confirmed` |
| OS command injection | critical | CWE-78 | exec marker outruns control marker -> `confirmed` |
| Server-side template injection | critical | CWE-1336 | `{{7*7}}` evaluates to 49 -> `confirmed` |
| CRLF injection / response splitting | high | CWE-113 | injected header materializes -> `confirmed` |
| TRACE method enabled (XST surface) | high | CWE-693 | marker header echoed back by TRACE -> `confirmed` |
| Risky HTTP methods advertised | medium | CWE-650 | Allow header lists TRACE/PUT/DELETE -> `likely` |
| XML external entity injection | high | CWE-611 | local file content returned via entity -> `confirmed` |
| SSRF (out-of-band confirmed) | high | CWE-918 | OOB listener received the callback -> `confirmed` |
| Host header injection | high | CWE-640 | marker domain echoed vs baseline -> `confirmed` |
| HTTP parameter pollution | medium | CWE-235 | both injected values land, in order -> `confirmed`; last-value echo -> `needs-manual` |
| CORS origin reflection | high | CWE-942 | arbitrary origin reflected + credentials -> `confirmed` |
| LDAP injection | medium | CWE-90 | differential response to LDAP metacharacters -> `likely` |
| NoSQL injection | medium | CWE-943 | MongoDB operators change response -> `likely` |
| Format string injection | high | CWE-134 | new hex values after `%x` -> `confirmed` |
| Email/user enumeration | medium | CWE-204 | differential response for unknown identities -> `likely` |
| Open redirect | medium | CWE-601 | 3xx Location to probe host -> `confirmed` |
| Path traversal | high | CWE-22 | OS file indicators -> `confirmed` |
| XPath injection | high | CWE-643 | fresh XML parser error vs baseline -> `confirmed` |
| Server-side includes injection | high | CWE-96 | `exec` marker printed without the raw directive -> `confirmed` |
| Log4Shell (JNDI injection) | critical | CWE-917 | JNDI lookup reached the raw listener -> `confirmed` |
| Shellshock (Bash command injection) | critical | CWE-78 | crafted header triggered an HTTP callback -> `confirmed` |
| Blind XXE | high | CWE-611 | external entity fetched by the target -> `confirmed` |

## Authorization checks

| Check | Severity | CWE | Confirmation basis |
|---|---|---|---|
| Broken access control (BOLA/IDOR) | critical | CWE-639 | identical response for low-privilege role -> `confirmed` |
| Authorization response differs | low | CWE-639 | same status, different body -> `needs-manual` |
| Session fixation | low | CWE-384 | session cookie not regenerated -> `needs-manual` |
| JWT uses alg:none | critical | CWE-347 | JWT header analysis -> `confirmed` |
| JWT alg:none attack accepted | critical | CWE-347 | forged token accepted by server -> `confirmed` |
| JWT uses HMAC | low | CWE-326 | JWT header analysis -> `needs-manual` |
| Form missing CSRF token | medium | CWE-352 | POST/password form without CSRF field -> `likely` |

## Link health checks

| Check | Severity | CWE | Confirmation basis |
|---|---|---|---|
| Link to dead domain (hijack) | high | CWE-350 | DNS failure, verified twice -> `confirmed` |
| Link to parked domain (hijack) | high | CWE-350 | tight parking fingerprints -> `confirmed` |
| Broken outbound link | medium | CWE-350 | HTTP 404/410 -> `confirmed` |
| Unreachable outbound link | low | CWE-350 | fails after retry -> `likely` |
| Outbound link to private IP | info | CWE-918 | DNS resolution -> `confirmed`, never fetched |

## Fuzz and origin checks

| Check | Severity | CWE | Confirmation basis |
|---|---|---|---|
| Directory fuzz | info | CWE-538 | status + wildcard baseline |
| Payload divergence | low | CWE-200 | status/size shift vs the control request -> `needs-manual` |
| Sensitive file exposure (.env, .git, backups) | high | CWE-538 | content signature, not just 200 -> `confirmed` |
| Directory listing enabled | medium | CWE-548 | listing content signature -> `confirmed` |
| GraphQL introspection enabled | low | CWE-200 | real `__schema` payload -> `confirmed` |
| GraphQL field suggestions | low | CWE-200 | "Did you mean" on an invalid field -> `confirmed` |
| Subdomain takeover via CNAME | critical | CWE-350 | CNAME + unclaimed service page -> `confirmed` |

## YAML templates

The 37 bundled Nuclei-style templates run with every scan by default. They cover the CVE checks above plus default admin panels, Spring Boot actuator, Docker/Kubernetes APIs, source maps, WordPress user enumeration, exposed Symfony profiler, Go pprof, Swagger UI, ASP.NET trace, ELMAH, Tomcat examples, permissive crossdomain policy, WordPress XML-RPC and phpMyAdmin setup. v1.4 adds Git metadata, .env, AWS credentials, SSH private keys, SQL backups, phpinfo, Apache server-status, etcd, Consul, Docker registry, and Jupyter contents checks.

Every template states its confidence rule; HIGH/CRITICAL templates cannot load without one. `--no-templates` skips the bundle, `--templates FILE_OR_DIR` adds custom templates, and `summit templates` lists or validates them.
