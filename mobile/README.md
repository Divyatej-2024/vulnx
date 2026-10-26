# VulnX Mobile

This is a standalone Expo / React Native application for Android and iOS. It uses the existing VulnX API and does not depend on the React web frontend.

## Run on a phone

Requirements: Node.js LTS, this repository, and Expo Go installed on the phone.

1. Install dependencies from this directory:

   ```powershell
   cd C:\Users\pdivy\vulnx\mobile
   npm install
   ```

2. Configure the API URL. Either copy `.env.example` to `.env` and set `EXPO_PUBLIC_API_URL`, or launch without it and enter the API address in the app. For a local backend on the same Wi-Fi, use the computer's LAN IPv4 address, for example `http://192.168.1.20:8000/api/v1`. Start FastAPI with `uvicorn app.main:app --reload --host 0.0.0.0` from the `backend` directory. For a phone to fetch live data from anywhere without the web frontend, deploy the dedicated API stack below and set this to its public HTTPS API URL.

3. Start Expo:

   ```powershell
   npx expo start
   ```

   Scan the QR code with Expo Go. The phone and development computer should be on the same Wi-Fi. If local network discovery is blocked, use `npx expo start --tunnel`.

## Google Play release preparation

The Android app uses Expo / React Native (not a web wrapper). The current application ID is `com.vulnx.mobile`; confirm that this is the final permanent ID before first Play submission. The app is configured for Android target API 36 and requests internet access only, while blocking unrelated sensitive permissions where supported by Expo config. Release builds require an HTTPS API URL. Review the in-app privacy acknowledgement and `../frontend/vulnx-ui/public/privacy.html` before publishing; the privacy policy must match the final infrastructure and all bundled dependencies. Build an Android App Bundle with the `production` EAS profile, test the exact bundle on devices, and complete Play Console's Data safety, app content, target audience, content rating, privacy-policy, and signing steps. Never upload signing credentials to Git.

## Features

- CVE list with search, severity filters, and paginated loading
- CVSS severity, publication date, summary counts, and CVE detail sheet
- Pull to refresh, automatic refresh every five minutes, and refresh when the app returns to the foreground
- Locally saved API address and cached records for viewing when temporarily offline

The backend updater is a separate service. Run the local Windows scheduled task or deploy the Docker Compose updater from the repository root to refresh NVD data daily.

## Independent live API deployment

The mobile app calls the VulnX API directly; it does not need the web frontend. To host a separate API and automatic NVD updater, use the root `docker-compose.mobile-api.yml` stack on a Linux server with Docker Compose and a domain name:

1. Point the domain's DNS A record to the server's public IP. Allow inbound TCP ports 80 and 443 in the server firewall.
2. Copy the root `.env.mobile-api.example` to `.env.mobile-api` and set `VULNX_API_DOMAIN` to your API domain.
3. From the repository root, start the API, updater, and HTTPS proxy:

   ```sh
   docker compose --env-file .env.mobile-api -f docker-compose.mobile-api.yml up -d --build
   ```

   Caddy obtains and renews the HTTPS certificate. The updater shares the API's persistent database volume and begins refreshing NVD data at startup, then repeats at the configured interval.
4. Confirm `https://YOUR_API_DOMAIN/api/v1/health` returns `{"status":"ok"}` and `https://YOUR_API_DOMAIN/api/v1/summary` reports a nonzero `total` after the initial feed import.
5. Set `EXPO_PUBLIC_API_URL` to `https://YOUR_API_DOMAIN/api/v1` in the EAS production environment before building, or enter that address in the mobile app's connection settings during development. The production app can then reach live data independently of the web frontend.

Keep `.env.mobile-api` private if it contains deployment-specific values. The example file is safe to commit.

## Build installable apps

Expo Go is for development. To build an Android APK for direct installation, configure an Expo account and run:

```powershell
npx eas-cli@latest login
npx eas-cli@latest build --platform android --profile preview
```

For store submission, use the `production` EAS profile. iOS device builds and App Store distribution need the corresponding Apple signing and developer account setup. Set `EXPO_PUBLIC_API_URL` to the deployed HTTPS API before creating a standalone build.
