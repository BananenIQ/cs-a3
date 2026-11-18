"""
HTTP Message Signatures (RFC 9421) mit RSASSA-PSS / SHA-512.

Ablauf:
  1. RSA-Schlüsselpaar laden (oder beim ersten Start erzeugen).
  2. POST-Request mit JSON-Body an https://httpbin.org/anything?uid=PollyTiker bauen.
  3. Request nach RFC 9421 signieren. Abgedeckte Komponenten:
     @method, @target-uri, date, host, content-type, content-length
     + content-digest (RFC 9530), das den Body an die Signatur bindet.
  4. Request absenden.
  5. Aus der JSON-Antwort von httpbin den empfangenen Request nachbauen und
     die Signatur mit dem öffentlichen Schlüssel prüfen (plus Gegenprobe mit
     manipulierten Daten).

Bibliotheken: requests-http-signature 2.x / http-message-signatures 3.x (pyauth)
"""

import json
import sys
from pathlib import Path

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from http_message_signatures import InvalidSignature, MappingKeyResolver, algorithms
from requests_http_signature import HTTPSignatureAuth

URL = "https://httpbin.org/anything?uid=PollyTiker"
KEY_ID = "polly-tiker-rsa-pss"
ALGORITHM = algorithms.RSA_PSS_SHA512  # alg="rsa-pss-sha512"

PRIVATE_KEY_FILE = Path(__file__).with_name("key.pem")
PUBLIC_KEY_FILE = Path(__file__).with_name("key.pub.pem")

# Geschützte Nachrichtenteile (Reihenfolge = Reihenfolge in der Signaturbasis)
COVERED_COMPONENTS = (
    "@method",         # Method
    "@target-uri",     # Target URI
    "date",            # Date
    "host",            # Host
    "content-type",    # Content-Type
    "content-length",  # Content-Length
    "content-digest",  # Hash des Bodys -> Body ist mitsigniert
)


def load_or_create_keys() -> tuple[bytes, bytes]:
    """Liefert (private_pem, public_pem). Erzeugt bei Bedarf ein RSA-4096-Schlüsselpaar."""
    if PRIVATE_KEY_FILE.exists() and PRIVATE_KEY_FILE.stat().st_size > 0:
        private_pem = PRIVATE_KEY_FILE.read_bytes()
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            sys.exit(f"{PRIVATE_KEY_FILE.name} enthält keinen RSA-Schlüssel.")
    else:
        print(f"Erzeuge neues RSA-4096-Schlüsselpaar -> {PRIVATE_KEY_FILE.name}, {PUBLIC_KEY_FILE.name}")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        PRIVATE_KEY_FILE.write_bytes(private_pem)

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    PUBLIC_KEY_FILE.write_bytes(public_pem)
    return private_pem, public_pem

def build_request() -> requests.PreparedRequest:
    """POST-Request mit JSON-Body. Content-Length setzt requests beim Vorbereiten."""
    body = json.dumps(
        {"is_god_real": None, "task": "RFC 9421", "algo": "rsa-pss-sha512"},
        ensure_ascii=False,
    ).encode("utf-8")
    return requests.Request(
        method="POST",
        url=URL,
        headers={
            # Host explizit setzen, damit er schon beim Signieren im Request steht
            # (sonst fügt urllib3 ihn erst beim Senden hinzu).
            "Host": "httpbin.org",
            "Content-Type": "application/json",
        },
        data=body,
    ).prepare()


def sign_request(request: requests.PreparedRequest, private_pem: bytes) -> None:
    """Signiert den Request in place und gibt die Signaturbasis aus."""
    auth = HTTPSignatureAuth(
        signature_algorithm=ALGORITHM,
        key_id=KEY_ID,
        covered_component_ids=COVERED_COMPONENTS,
        label="sig1",
    )
    # prepare(): setzt Date + Content-Digest und erzeugt die Signaturbasis (RFC 9421, Abschnitt 2.5)
    prepared = auth.prepare(request)
    print("=== Signaturbasis ===")
    print(prepared.signature_base.decode())
    print()

    # RSASSA-PSS mit SHA-512 (MGF1-SHA-512, Salt-Länge 64 Byte) über die Signaturbasis
    signature = ALGORITHM(private_key=private_pem).sign(prepared.signature_base)

    # apply(): setzt die Header Signature-Input und Signature
    auth.apply(request, prepared, signature)


def print_request(request: requests.PreparedRequest) -> None:
    print("=== Gesendeter Request ===")
    print(f"{request.method} {request.url}")
    for name, value in request.headers.items():
        print(f"{name}: {value}")
    print()
    print(request.body.decode())
    print()


def request_from_echo(echo: dict, *, body: str | None = None, url: str | None = None) -> requests.PreparedRequest:
    """Baut den bei httpbin angekommenen Request aus dessen JSON-Echo nach."""
    return requests.Request(
        method=echo["method"],
        url=url or echo["url"],
        headers=echo["headers"],
        data=(echo["data"] if body is None else body).encode("utf-8"),
    ).prepare()


def verify(request: requests.PreparedRequest, public_pem: bytes):
    return HTTPSignatureAuth.verify(
        request,
        signature_algorithm=ALGORITHM,
        # Prüfer kennt nur den öffentlichen Schlüssel
        key_resolver=MappingKeyResolver(private_keys={}, public_keys={KEY_ID: public_pem}),
        require_components=COVERED_COMPONENTS,
    )


def check_echo(sent: requests.PreparedRequest, echo: dict, public_pem: bytes) -> bool:
    headers = {k.lower(): v for k, v in echo["headers"].items()}
    ok = True

    def check(label: str, condition: bool, detail: str = "") -> None:
        nonlocal ok
        ok &= condition
        print(f"  [{'OK' if condition else 'FEHLER'}] {label}{f'  ({detail})' if detail else ''}")

    print("=== Prüfung der JSON-Antwort ===")
    check("Methode", echo["method"] == sent.method, echo["method"])
    check("URL", echo["url"] == sent.url, echo["url"])
    check("Query-Parameter uid", echo["args"].get("uid") == "PollyTiker", str(echo["args"]))
    check("Body (JSON)", echo["json"] == json.loads(sent.body), echo["data"])
    for name in ("date", "host", "content-type", "content-length", "content-digest", "signature-input", "signature"):
        check(f"Header {name} unverändert angekommen", headers.get(name) == sent.headers.get(name))

    print()
    print("=== Signaturprüfung des empfangenen Requests (öffentlicher Schlüssel) ===")
    try:
        result = verify(request_from_echo(echo), public_pem)
    except InvalidSignature as e:
        check("Signatur gültig", False, str(e))
        return False
    check("Signatur gültig", True, f"label={result.label}, alg={result.parameters['alg']}")
    check("Body-Digest gültig", result.body == sent.body)
    print("  Signierte Komponenten:")
    for component, value in result.covered_components.items():
        print(f"    {component}: {value}")
    print(f"  Signaturparameter: {dict(result.parameters)}")

    print()
    print("=== Gegenprobe: manipulierte Requests müssen abgelehnt werden ===")
    tampered = {
        "Body geändert": request_from_echo(echo, body=echo["data"].replace("PollyTiker", "Mallory")),
        "Target URI geändert": request_from_echo(echo, url=echo["url"].replace("PollyTiker", "Mallory")),
    }
    for label, request in tampered.items():
        try:
            verify(request, public_pem)
            check(f"{label} -> abgelehnt", False, "Signatur wurde trotzdem akzeptiert!")
        except InvalidSignature as e:
            check(f"{label} -> abgelehnt", True, str(e) or type(e).__name__)
    return ok


def main() -> int:
    private_pem, public_pem = load_or_create_keys()

    request = build_request()
    sign_request(request, private_pem)
    print_request(request)

    with requests.Session() as session:
        response = session.send(request, timeout=30)
    print(f"=== Antwort: HTTP {response.status_code} ===")
    response.raise_for_status()
    echo = response.json()
    print(json.dumps(echo, indent=2, ensure_ascii=False))
    print()

    ok = check_echo(request, echo, public_pem)
    print()
    print("ERGEBNIS:", "alle Prüfungen bestanden" if ok else "mindestens eine Prüfung fehlgeschlagen")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
