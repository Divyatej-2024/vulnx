# Chromium browser testing

VulnX uses Playwright with its bundled Chromium browser for repeatable, isolated UI quality checks. This is a development/CI test harness; it does not add browser automation to the production API and does not scan arbitrary third-party websites.

## What is checked

- The React application mounts at the configured local URL.
- The document and body do not introduce horizontal overflow at 390px, 768px, and 1365px viewport widths.
- The page does not emit uncaught JavaScript errors during initial rendering.

## Run locally

From the repository root, install and start the existing frontend first:

```bash
cd frontend/vulnx-ui
npm ci
npm start
```

In a second terminal, from the repository root:

```bash
python -m pip install -r tests/browser/requirements.txt
python -m playwright install chromium
python -m pytest -q tests/browser
```

Set `VULNX_BASE_URL` to override the default `http://127.0.0.1:3000` URL. Only point this test harness at an application instance you own or are authorised to test.

The GitHub Actions workflow `.github/workflows/chromium-ui.yml` runs the same checks on pull requests, pushes to `main`, and manual dispatch. Browser binaries are installed by the workflow and are not part of the production container image.

## Scope and limitations

These are smoke and responsive-layout checks, not a penetration test, accessibility certification, or proof that every dialog and data state is correct. Add focused tests for specific dialogs after stable selectors and expected UI states are identified. Production browser automation is intentionally kept out of the FastAPI request path.
