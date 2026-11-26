import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, build_opener, ProxyHandler

BASE = "http://192.168.0.1"
OUTPUT = Path("findings/album_baseline_2026-11-20")

ASSETS = {
    "/index.html": "index.html",
    "/js/index.js": "index.js",
    "/styles/index.css": "index.css",
    "/data.json": "data.json",
}

def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    opener = build_opener(ProxyHandler({}))
    manifest = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "console_firmware": "22.5.0",
        "hardware": "HAC-001 / Tegra X1 Erista",
        "base_url": BASE,
        "responses": {},
    }

    for endpoint, filename in ASSETS.items():
        request = Request(
            BASE + endpoint,
            headers={"Connection": "close",
                     "User-Agent": "Switch-Album-Research/1.0"},
        )

        try:
            with opener.open(request, timeout=5) as response:
                body = response.read()
                target = OUTPUT / filename
                target.write_bytes(body)

                manifest["responses"][endpoint] = {
                    "status": response.status,
                    "content_type": response.headers.get("Content-Type"),
                    "length": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "saved_as": str(target),
                }

                print(f"[OK] {endpoint}: {len(body)} bytes")

                if endpoint == "/data.json":
                    data = json.loads(body)
                    manifest["album_metadata"] = {
                        "file_type": data.get("FileType"),
                        "console_name": data.get("ConsoleName"),
                        "file_count": len(data.get("FileNames", [])),
                    }

        except Exception as exc:
            manifest["responses"][endpoint] = {"error": str(exc)}
            print(f"[ERROR] {endpoint}: {exc}")

    manifest_path = OUTPUT / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"\nManifest saved: {manifest_path}")

if __name__ == "__main__":
    main()
