# VulnX Google Play, privacy and security readiness

Status: preparation checklist, not a statement of Play approval or a completed security audit. Reviewed against repository structure on 26 October 2026.

## Architecture observed
- React 19 / Create React App frontend at `frontend/vulnx-ui`.
- FastAPI backend with `/api/v1` routes.
- PWA manifest and service worker exist for the web app.
- A separate native Android app lives in `mobile/` and uses Expo / React Native; it is not a web wrapper.
- The mobile app requests public CVE data from a configured API, caches public records and settings locally, and displays a privacy acknowledgement.
- No mobile account-registration, advertising or intentional analytics feature is described in the current app. Recheck the final AAB, dependency tree, backend and hosting integrations before submission.

## Native Android release sequence

1. **Confirm the public privacy policy.** Open `https://vulnx-six.vercel.app/privacy.html` in a normal browser and verify it loads over HTTPS, is publicly accessible without sign-in or geographic restrictions, and accurately describes the final app and infrastructure. The source file is present in this repository, but a successful Vercel deployment alone does not prove that the live page is correct.
2. **Confirm the app identity.** Current Android application ID: `com.vulnx.mobile`. Treat it as permanent before the first Play upload; changing it later creates a different Play app.
3. **Confirm the API endpoint.** Set `EXPO_PUBLIC_API_URL` to the deployed API base ending in `/api/v1` in the EAS production environment, or verify that the app's connection setup provides an appropriate HTTPS endpoint. This value is public app configuration, not a secret. Do not put credentials or private keys in `EXPO_PUBLIC_*` variables.
4. **Inspect the generated Android manifest.** From `mobile/`, install the locked dependencies with `npm ci`, then run `npx expo prebuild --platform android` and inspect `android/app/src/main/AndroidManifest.xml`. Check the final merged manifest and dependency-added permissions; configuration exclusions alone do not prove the final package has no extra permissions. The current config explicitly requests internet access and blocks several unrelated sensitive permissions.
5. **Run release QA.** Run `npx expo config --type public` and `npx expo export --platform android`. Then run the EAS preview build and install it on a physical Android device. Test first launch/privacy acknowledgement, policy link, API connection, search, severity filtering, CVE details, pagination, refresh, offline cache, invalid server URL and recovery from API failure.
6. **Build the store artifact.** Sign in to the Expo account associated with the configured EAS project, then from `mobile/` run `npm run build:android:production`. The expected store artifact is a signed Android App Bundle (AAB), not the preview APK. Verify the build completes and download the AAB from the EAS build page. Never commit or share signing credentials, access tokens or keystore files.
7. **Review supply-chain licensing and security.** Audit direct and transitive npm/Android dependencies, fonts, icons and other assets. The root project has an MIT licence, but that does not change third-party licences. Generate an SBOM and review actionable dependency findings before submission.
8. **Use Play internal testing first.** Upload the AAB to an internal-testing track, install it through the Play testing flow, and verify the installed package, signing, supported Android versions, crash/error behaviour and privacy links before considering production release.
9. **Check current Play requirements again at submission.** As of 31 August 2026, official Android guidance says new apps and updates must target Android 16 / API 36 or higher, subject to form-factor exceptions. The current config targets API 36; confirm that requirement has not changed before submitting.

Expo build documentation: https://docs.expo.dev/build/setup/
Android app bundle guidance: https://developer.android.com/guide/app-bundle
Google Play policy centre: https://support.google.com/googleplay/android-developer/answer/10144311

## Privacy and consent
- Enter the exact public HTTPS privacy-policy URL in Play Console only after checking the live page and matching it to actual production behaviour.
- The in-app notice is an acknowledgement of current privacy information, not consent to optional tracking.
- Verify what Vercel, Supabase, the API runtime, monitoring integrations and all third-party resources actually collect and retain. Exact log fields and retention periods cannot be inferred from repository source alone.
- Consider self-hosting Google Fonts to reduce third-party browser requests.
- Complete Play Console Data safety based on the final AAB, backend, hosting and every SDK; do not guess.
- The current app has no account feature. If accounts are introduced later, implement account deletion and update the privacy policy before release.
- Configure a monitored privacy contact and a private security-reporting channel before publishing. Public repository issues should not be used for sensitive reports.

## Security controls to implement and verify

### Frontend and delivery
- Enforce HTTPS and redirect HTTP to HTTPS.
- Add host-level headers where supported: Content-Security-Policy (begin report-only), Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy and restrictive Permissions-Policy.
- Test CSP against React assets, API requests and Google Fonts before enforcement; avoid unsafe-inline/eval unless required and justified.
- Keep service-worker cache limited to static assets and public CVE data. Never cache future authentication tokens or sensitive account responses.
- For external links opening new tabs, use `rel="noopener noreferrer"`.

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
- [ ] Public privacy policy URL verified live and matching actual practices.
- [ ] Data safety form completed for the exact AAB and all SDKs.
- [ ] App content declarations: ads, target audience, content rating, app access and relevant policy declarations.
- [ ] Permissions reviewed against the final merged Android manifest.
- [ ] Target API confirmed against current Play rules.
- [ ] AAB signing and Play App Signing verified.
- [ ] Internal testing across supported Android versions and screen sizes.
- [ ] Offline/error states, accessibility, privacy acknowledgement and links tested.
- [ ] Root MIT licence retained; third-party dependency and asset licence audit completed.
- [ ] Privacy/security contact monitored.
- [ ] Store listing claims only features actually implemented.

## Known release blockers as of this review
- Live privacy-policy rendering has not been independently verified by the web-checking tool; manually confirm it in a browser.
- The final merged Android manifest has not yet been inspected.
- A signed production AAB and physical-device test have not yet been verified.
- Provider logging, retention, backups, monitoring and the full dependency licence inventory require operator-side confirmation.
- Play Console declarations and internal testing remain to be completed.
