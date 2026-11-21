# Security Policy

## Scope

PhishWatch is a local learning and defensive-research project, not a production phishing-analysis service. Keep it bound to localhost and use only systems and accounts you own or are authorized to test.

## Reporting a vulnerability

Please do not publish sensitive exploit details in a public issue. Use GitHub's private vulnerability reporting feature for this repository if it is enabled. If private reporting is unavailable, contact the repository owner privately before sharing technical details.

## Design boundaries

- No credential, OTP, cookie, authorization-header, message-content, raw user-agent or IP-address storage. A limited user-agent string is examined in memory for classification only.
- No attempts to bypass email security gateways, link scanners, spam filters or browser protections.
- Request classifications are heuristic signals, not proof of a human click or automated visit.
- The default server bind address is 127.0.0.1. Do not expose it to an untrusted network.
