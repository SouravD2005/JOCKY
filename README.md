# JOCKY — Forensic Intelligence Console

Interactive prototype for authorized cross-platform digital-forensics orchestration. It demonstrates the JOCKY workflow: forensic intent → validated plan → simulated Windows/Linux adapter execution → normalized evidence → timeline and graph correlation.

## Run locally

```bash
npm install
npm run dev
```

Open `http://127.0.0.1:5173`.

## Demo flow

1. In **JOCKY Studio**, edit or validate the typed forensic-intent script.
2. Select the authorized target scope and choose **Run investigation**.
3. Observe multi-host collection and integrity-signing progress.
4. Open **Timeline** for the normalized sequence or **Correlation Graph** for linked evidence.

The UI deliberately uses an allowlisted operation model; it contains no arbitrary shell execution or security-control bypass features.
