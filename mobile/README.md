# VulnX Mobile

This is a standalone Expo / React Native application for Android and iOS. It uses the existing VulnX API and does not depend on the React web frontend.

## Run on a phone

Requirements: Node.js LTS, this repository, and Expo Go installed on the phone.

1. Install dependencies from this directory:

   ```powershell
   cd C:\Users\pdivy\vulnx\mobile
   npm install
   ```

2. Configure the API URL. Either copy `.env.example` to `.env` and set `EXPO_PUBLIC_API_URL`, or launch without it and enter the API address in the app. For a local backend on the same Wi-Fi, use the computer's LAN IPv4 address, for example `http://192.168.1.20:8000/api/v1`. Start FastAPI with `uvicorn app.main:app --reload --host 0.0.0.0` from the `backend` directory.

3. Start Expo:

   ```powershell
   npx expo start
   ```

   Scan the QR code with Expo Go. The phone and development computer should be on the same Wi-Fi. If local network discovery is blocked, use `npx expo start --tunnel`.

## Features

- CVE list with search, severity filters, and paginated loading
- CVSS severity, publication date, summary counts, and CVE detail sheet
- Pull to refresh, automatic refresh every five minutes, and refresh when the app returns to the foreground
- Locally saved API address and cached records for viewing when temporarily offline

The backend updater is a separate service. Run the local Windows scheduled task or deploy the Docker Compose updater from the repository root to refresh NVD data daily.

## Build installable apps

Expo Go is for development. To build an Android APK for direct installation, configure an Expo account and run:

```powershell
npx eas-cli@latest login
npx eas-cli@latest build --platform android --profile preview
```

For store submission, use the `production` EAS profile. iOS device builds and App Store distribution need the corresponding Apple signing and developer account setup. Set `EXPO_PUBLIC_API_URL` to the deployed HTTPS API before creating a standalone build.
