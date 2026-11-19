# HW08 — Scapy + Google Gruyere

Capture and inspect HTTP traffic from a local Gruyere instance.

## Files

- `http_capture.py` — Scapy sniff to pcap
- `http_analyze.py` — parse HTTP from pcap (gzip supported)
- `http_tap.py` — local tap `browser:8080 -> Gruyere:8008` (Windows loopback sniff was unreliable)
- `HW08_tap.pcap` — captured session
- `requirements.txt`

## Run

```bash
pip install -r requirements.txt
```

Local Gruyere (Python 2.7, port 8008):  
https://google-gruyere.appspot.com/gruyere-code.zip

Cloud Gruyere is HTTPS, so bodies are encrypted. This homework used a local HTTP instance.

Capture with tap:

```bash
python http_tap.py --listen 8080 --upstream-port 8008 --pcap HW08_tap.pcap
```

Open `http://127.0.0.1:8080/<id>/`, click around, then stop the tap.

Analyze:

```bash
python http_analyze.py HW08_tap.pcap
python http_analyze.py HW08_tap.pcap --needle "alert"
```

## Traffic notes (HW08_tap.pcap)

Normal browsing: `GET /`, `/login`, `/newaccount.gtl`, static files.

Login/signup went as GET with query params, e.g. `uid=test&pw=test` (lab account).

XSS-related traffic:

- `GET /newsnippet2?snippet=...` — payload in the `snippet` query parameter
- `GET /%3Cscript%3Ealert(1)%3C/script%3E` — payload in the path

In the responses the same strings show up in the HTML body (reflected). Compared to a normal page load, the request URL is longer and the response HTML contains the injected text.

There is also noise: many `HEAD *.sql` probes hitting the local port (501). Not from the Gruyere UI.
