# VulnX Google Play, privacy and security readiness

Status: preparation checklist, not a statement of Play approval or a completed security audit. Reviewed against repository structure on 26 October 2026.

## Architecture observed
- React 19 / Create React App frontend at frontend/vulnx-ui.
- FastAPI backend with /api/v1 routes.
- PWA manifest and service worker exist.
- Frontend requests public CVE data and caches app/feed data for offline use.
- No account registration, advertising SDK or analytics SDK was identified in the frontend package manifest reviewed. Recheck the full production bundle, backend and hosting before submission.

## Android route
Evaluate a Trusted Web Activity (TWA) first because VulnX is already a web app. Do not publish a thin wrapper until it provides a reliable and useful experience and meets Play quality requirements.

1. Confirm the canonical production domain and HTTPS for all app routes.
2. Run a PWA/Lighthouse audit; verify manifest, icons, start URL, responsive layout, offline/error states and accessibility.
3. Select a stable Android application ID before generating the project.
4. Generate a TWA using Bubblewrap or PWA Builder and inspect the Android manifest and dependencies.
5. Publish Digital Asset Links at /.well-known/assetlinks.json for the exact domain, package name and SHA-256 signing-certificate fingerprint.
6. Verify that the fingerprint matches the Play-distributed app signing certificate, not only a local upload key.
7. Build a signed Android App Bundle (AAB), test physical devices/emulators and use Play internal testing before production.
8. Recheck current target API requirements at submission. As of 31 August 2026, official Android guidance says new apps and updates must target Android 16 / API 36 or higher, subject to form-factor exceptions.
9. Avoid native permissions unless an actual native feature needs them.

Official guide: https://developer.android.com/develop/ui/views/layout/webapps/guide-trusted-web-activities-version2

## Privacy and consent
- Publish public/privacy.html at a stable, public, non-geo-fenced HTTPS URL and enter the exact URL in Play Console.
- The in-app notice is acknowledgement of current privacy information, not consent to optional tracking.
- Verify what the actual hosting, CDN, API, database, error-monitoring tools and all third-party resources collect and retain. Update the policy to identify real providers, purposes, retention, sharing and contact details.
- Consider self-hosting Google Fonts.
- Complete Play Console Data safety based on the final AAB, backend, hosting and every SDK; do not guess.
- The current frontend has no account feature. If accounts are introduced, implement in-app account deletion and an external deletion-request URL, and actually delete associated data or document a lawful retention exception.
- Configure a monitored privacy/security contact before publishing; repository issues are a temporary public contact route.

Official policy: https://support.google.com/googleplay/android-developer/answer/10144311

## Security controls to implement and verify

### Frontend and delivery
- Enforce HTTPS and redirect HTTP to HTTPS.
- Add host-level headers where supported: Content-Security-Policy (begin report-only), Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy and restrictive Permissions-Policy.
- Test CSP against React assets, API requests and Google Fonts before enforcement; avoid unsafe-inline/eval unless required and justified.
- Keep service-worker cache limited to static assets and public CVE data. Never cache future authentication tokens or sensitive account responses.
- For external links opening new tabs, use rel="noopener noreferrer".

### API and data
- Keep CORS restricted to exact production origins; do not combine wildcard origins with credentials.
- Validate query lengths, page limits, severity values, CVE identifiers and request sizes.
- Add rate limiting and timeouts at the edge/API where appropriate.
- Return generic production errors; do not expose stack traces, SQL, environment variables or secrets.
- Use least-privilege database credentials, encrypted transport, secret rotation, backups and restore tests.
- Ensure health/readiness checks do not leak infrastructure details.
- Never place API keys, database URLs or signing keys in frontend variables or committed files.

### Supply chain and testing
- Scan Python and npm dependencies; review actionable high/critical findings instead of blindly upgrading everything.
- Generate an SBOM and audit direct/transitive dependency, font, icon and Android SDK licences.
- Add tests for privacy notice, policy link, API validation, CORS and error states.
- Perform accessibility, OWASP web testing, Android compatibility and manual review before release.

## Play Console checklist
- [ ] Developer account and verified contact details.
- [ ] Stable package/application ID.
- [ ] App name, description, screenshots, icon, feature graphic and support contact.
- [ ] Public privacy policy URL matches actual practices.
- [ ] Data safety form completed for the exact build and all SDKs.
- [ ] App content declarations: ads, target audience, content rating, app access and relevant policy declarations.
- [ ] Permissions reviewed against final Android manifest; remove unused permissions.
- [ ] Target API confirmed against current Play rules.
- [ ] AAB signing and Play App Signing verified.
- [ ] TWA Digital Asset Links verified against Play app-signing certificate.
- [ ] Internal testing across supported Android versions and screen sizes.
- [ ] Offline/error states, accessibility, privacy notice and links tested.
- [ ] Third-party licence notices included where required.
- [ ] Privacy/security contact monitored.
- [ ] Store listing claims only features actually implemented.

## Licence decision
No root project LICENSE file was present in the root directory listing reviewed. Do not assume VulnX source code is MIT or Apache licensed. Choose and add a project licence only after deciding how others may use, modify and redistribute your code. Audit third-party dependency licences independently; a project licence does not replace Play policy compliance or legal review.
