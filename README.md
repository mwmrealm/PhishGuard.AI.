# PhishGuard AI — PWA Edition

A responsive, installable Progressive Web App for Windows desktop browsers and Android Chrome. The project is split into a static PWA frontend (GitHub Pages) and an optional Python/Flask API (Render or another Python host).

## What is included

- PWA manifest, 192/512 app icons, Apple touch icon and service worker.
- Responsive interface with dark mode, single scan, batch scan and CSV upload.
- Offline app-shell caching. Browser-side fallback checks can still scan pasted text without the API.
- Flask API wrapper around the supplied `detector.py` and `model.pkl`.
- CORS configuration, request-size limits and a health endpoint.
- Render deployment blueprint.

## Important architecture note

**GitHub Pages only hosts static files. It does not run Python, Flask, scikit-learn or your `.pkl` model.** The PWA therefore runs basic browser-side checks when no API URL is configured. To use the full existing rule engine plus ML prediction, deploy `backend/` as a separate Python web service and configure its URL in `config.js`.

The app shell and its static assets are cached for offline launch after the first successful visit. AI/backend scans need internet access and a running API. The browser fallback is a smaller heuristic implementation and is not equivalent to the full Python detector.

## 1. Deploy the PWA to GitHub Pages

1. Create a new GitHub repository, for example `phishguard-ai`.
2. Upload the **contents of this project folder** to the repository root (so `index.html` is at the root).
3. Open **Settings → Pages**.
4. Under **Build and deployment**, choose **Deploy from a branch**.
5. Select branch `main` and folder `/ (root)`, then Save.
6. Wait for GitHub Pages to publish the site. Open the URL shown in the Pages section.

The app uses relative paths, so it supports both a user/organization Pages site and a project Pages URL such as `https://username.github.io/phishguard-ai/`.

PWA installation requires HTTPS. GitHub Pages supplies HTTPS automatically. Do not test installability by opening `index.html` directly as a `file://` URL.

## 2. Deploy the AI backend

### Option A — Render (blueprint)

1. Push this project to GitHub.
2. In Render, create a **Blueprint** and select the repository.
3. Render reads `render.yaml` and creates the `phishguard-ai-api` web service.
4. Wait for deployment. Open `https://YOUR-SERVICE.onrender.com/health`; it should return JSON with `"status":"ok"`.

The `backend/model.pkl` file is included from your upload. Python pickle models can be sensitive to scikit-learn version changes. If loading fails, check the service logs and retrain with a compatible scikit-learn version and a training CSV.

### Option B — Run locally / another Python host

```bash
cd backend
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

The API listens on `http://127.0.0.1:5000`. For a production host use a WSGI server such as `gunicorn app:app` (or the host's documented Windows equivalent).

### Connect the PWA to the API

After Render finishes creating the backend service, open its service page and copy the exact `onrender.com` service URL. Check that `https://YOUR-SERVICE.onrender.com/health` returns JSON with `"status":"ok"`. Then edit `config.js` in the repository root and set:

```js
window.PHISHGUARD_API_BASE = "https://YOUR-SERVICE.onrender.com";
```

Do not use the GitHub Pages URL or a guessed Render URL here. Commit and push the change, then reload the PWA. The header should say **AI backend connected**; if it says **AI backend unavailable**, check the Render `/health` endpoint and the browser console for a CORS error. If the frontend is hosted at GitHub Pages and the backend at another domain, the backend must allow the frontend origin through `PHISHGUARD_ALLOWED_ORIGINS`.

For a more restrictive CORS setting, set the backend environment variable to the exact GitHub Pages origin, for example `https://username.github.io` (no path). The included Render blueprint defaults to `*` for easy first deployment; tighten it after setup.

## 3. Install on Windows

1. Open the published HTTPS URL in Microsoft Edge or Google Chrome.
2. Use the install icon in the address bar or the app's **Install app** button when shown.
3. Launch PhishGuard AI from the Start menu like a desktop app.

## 4. Install on Android

1. Open the published HTTPS URL in Chrome.
2. Tap the browser menu (⋮).
3. Choose **Install app** or **Add to Home screen**.
4. Confirm. Launch it from the home screen/app drawer.

The exact wording varies by Android and browser version.

## 5. Offline behaviour

- After the first successful online visit, the service worker caches the app shell, styles, scripts, manifest and icons.
- The app can reopen offline and perform its built-in browser-side heuristic checks.
- The full Python model, AI probability, and server-side CSV analysis require a reachable backend.
- Service-worker updates are applied when the browser detects the new version. If an old version remains, close and reopen the installed app or clear its site cache.

## Project layout

```text
PhishGuard-AI-PWA/
├── index.html
├── styles.css
├── app.js
├── config.js
├── manifest.webmanifest
├── sw.js
├── logo.png
├── icons/
│   ├── icon-192.png
│   ├── icon-512.png
│   └── apple-touch-icon.png
├── backend/
│   ├── app.py
│   ├── detector.py
│   ├── model.pkl
│   └── requirements.txt
└── render.yaml
```

## Security and limitations

- The scanner does not send, modify or delete emails. If configured, pasted email text is sent to your own API host for analysis; review that host's privacy, logging and retention settings before using sensitive messages.
- The model is advisory rather than definitive: its score is not calibrated and can be overconfident, so it cannot produce a **Dangerous** verdict by itself without rule-based warning signs. A high AI result with no rule signals is shown as **Suspicious**.
- Avoid scanning confidential or regulated email content unless your hosting and data-handling arrangements are appropriate.
- A verdict is an aid, not a guarantee. False positives and false negatives are possible.
- The supplied pickle is loaded by Python. Only load model files you trust.
- The large original `phishing_email.csv` was not copied into this package. It is not needed when the included model loads successfully. If retraining is required, provide a correctly labelled dataset on the backend host.
- `logo.png` is retained as supplied; generated PWA icon sizes are in `icons/`.

## Local browser preview

For PWA/service-worker testing, serve the project root over localhost rather than opening the file directly:

```bash
python -m http.server 8080
```

Then open `http://localhost:8080`. This preview uses browser-side fallback checks unless the API URL is configured.
