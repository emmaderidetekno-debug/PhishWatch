# Changelog

## 0.3.0

- Bind the server to localhost by default.
- Stop trusting the incoming Host header when constructing generated tracking links.
- Add security headers and no-store response caching.
- Validate campaign labels and URL API input types.
- Add readable campaign labels to activity records.
- Add JSON 404 responses and controlled malformed-JSON errors.
- Support isolated data directories for tests.
- Expand classifier and URL detector edge-case coverage.
- Add API integration and tracker persistence/retention tests.
- Run GitHub Actions tests on Node.js 22 and 24.

## 0.2.0

- Add transparent visit classification, confidence labels and evidence explanations.
- Keep normal browser-like GET requests unclassified.
- Add classifier tests and dashboard evidence columns.

## 0.1.0

- Initial controlled tracking and URL-risk analysis dashboard.
