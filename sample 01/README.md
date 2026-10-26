# Website Security Posture Checker

A responsive browser-based tool for a passive, informational review of selected public security signals. Visitors enter a homepage URL and receive a report with observed evidence, confidence, potential impact, and suggested next steps.

This tool is **not** a penetration tester, vulnerability scanner, audit, or guarantee that a website is safe or secure. Missing headers alone do not prove a vulnerability. Use it only on websites you own or have permission to assess.

## What it checks

- Whether the submitted homepage uses HTTPS or HTTP.
- Basic homepage response status and the presence of Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy, and framing controls.
- Secure, HttpOnly, and SameSite attributes exposed in homepage Set-Cookie headers.
- Potential `http://` references in homepage `src`, `href`, or `poster` attributes. Referenced resources are not requested.
- Availability and basic text handling of `/robots.txt` and `/.well-known/security.txt`.

It does not crawl links, guess paths, scan ports, exploit vulnerabilities, test credentials, bypass protections, or fetch page assets. Results can vary by time, location, and server configuration. TLS connection verification is performed by the HTTP runtime; this report does not claim a full certificate audit.

## Architecture and data flow

`static/index.html`, `static/styles.css`, and `static/app.js` provide the browser experience. The page posts only the entered URL to Flask at `/api/check`. `app.py` validates the URL, resolves and rejects non-public addresses before each request hop, performs bounded homepage and two fixed-path requests, parses response metadata, and returns a normalized JSON report. Submitted URLs and response bodies are not persisted; the app does not log the target itself. The browser renders report text with HTML escaping and can download a minimized JSON report.

The checker limits input length, response size (500 KB for homepage, 64 KB for each public file), redirects (3), request timeout (connect/read), concurrent assessments (4), and per-client request rate. DNS is resolved and every resulting address is checked at each redirect. DNS validation followed by the HTTP library's independent hostname resolution still leaves a small DNS-rebinding race; use a hardened outbound proxy or a resolver-pinning transport for public deployment. Keep outbound network egress restricted, add edge-level rate limits, and do not expose a debug server.

## AI improvement advice

After a passive assessment, visitors can request AI-generated defensive improvement ideas based on the current report. The app sends a compact, allow-listed subset of the report to the OpenAI Responses API; the API key remains on the server. The API request uses `store: false`, and this app does not write the submitted URL, report, or AI response to its own database or files. The advice is shown for the current browser session only. An external API request still transmits the report fields to OpenAI for processing, so avoid sending reports that contain information you do not want to share with that provider.

Set the key in the same PowerShell session before starting Flask:

```powershell
$env:OPENAI_API_KEY = "your-api-key"
# Optional: use a model available to your API project
$env:OPENAI_MODEL = "gpt-6-astra"
python app.py
```

Never put the API key in browser JavaScript, HTML, or a committed file. The AI feature returns a setup message if no key is configured. API use may incur charges under your OpenAI account. Check current API access and billing for your account.

The current backend is Flask/Python. Vercel supports Flask directly as a serverless function, so this project is prepared for Vercel deployment. Netlify does not run this Flask app as-is; deployment there would require porting the backend to Netlify Functions or hosting Python elsewhere.

## Scoring

Each applicable check has a documented integer weight in the report data. The summary is the rounded weighted fraction of checks marked `present` among checks with a `present` or `not_present` result. `unknown` and `not_applicable` results are excluded, never counted as failures. “Completed checks” counts applicable present/not-present observations. The score is not a probability, compliance result, or overall security rating; different sites need different controls.

## Setup and run

Requires Python 3.10 or newer.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>. The built-in server binds to loopback and is suitable for local demos only. Do not deploy it directly as a public service; use a production WSGI server plus controlled outbound networking, strict rate and concurrency limits, monitoring that excludes submitted URLs, and patched dependencies.

## Deploy for a mentor demo with Vercel

This project can be deployed as one Flask website on Vercel. The public browser files are in `public/`; `app.py` provides the Flask website and API. Vercel detects the Flask app at the project root, and the API key is supplied as a Vercel environment variable instead of being committed to GitHub.

1. Create a private or public GitHub repository and upload the contents of this project folder. Keep `.venv`, `.env`, and API keys out of the repository; `.gitignore` is included.
2. In Vercel, choose **Add New → Project**, import that GitHub repository, and deploy with the detected Python/Flask settings. No separate backend host is needed for this Vercel setup.
3. In the Vercel project settings, add `OPENAI_API_KEY` as a **Secret** environment variable for Production (and Preview if you want AI advice in previews). Optionally set `OPENAI_MODEL` to a model available to your OpenAI API project.
4. Redeploy after adding the key, then open the Vercel URL and try an authorized public website. The passive report works without an AI key; the AI advice button needs the key.
5. Share the Vercel deployment URL with your mentor.

Reports are not saved by this app. A visitor's report exists in the browser for the current session; when AI advice is requested, selected report fields are sent to OpenAI for processing and are not stored by this app. Vercel may retain its normal platform request/function logs; do not promise that infrastructure logs are never retained.

The same source can still run locally with `python app.py`. Vercel functions have platform limits and can cold start; keep the outbound request timeout/size limits in place. Use a production deployment only for authorized, low-volume demo use and review Vercel's current plan limits before public sharing.

## Tests

All outbound HTTP in tests is mocked. Tests do not contact real websites.

```powershell
python -m unittest -v
```

The suite covers URL and address validation, redirect rejection and limits, timeouts, response size, header/cookie parsing, framing evidence, scoring, unknown results, and the report API.

## Demo script

1. Start the local server and open the website.
2. Use a mock HTTP fixture in the test suite or a local controlled fixture reachable via a test-only mocked resolver. Production URL validation deliberately blocks local addresses.
3. Point out the authorization notice and the explicit checks list.
4. In the returned report, show the distinction between “Not present”, “Not applicable”, and “Could not check”, then download the JSON report.
5. Explain that results are a passive snapshot, not a claim that a site is secure.

For a live demo against a website, use a public site you own or have explicit permission to assess.
