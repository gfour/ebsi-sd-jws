import base64
import json
import hashlib
import os
from typing import Any, List, Tuple

from jose import jwk, jws, jwt

# Use example from:
# https://code.europa.eu/ebsi/ecosystem/-/blob/260d06744f9116fb73fe307e0a80e21315245dc9/drafts/draft-sd-jws.md
USE_EBIP_EXAMPLE = True

ALG = "ES256"
# Taken from: https://python-jose.readthedocs.io/en/latest/jwk/index.html
TEST_HMAC_KEY = {
    "kty": "oct",
    "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
    "use": "sig",
    "alg": "HS256",
    "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
}
TEST_KEY = jwk.construct(TEST_HMAC_KEY)


def to_compact_json(d) -> str:
    return json.dumps(d, separators=(',', ':'))


def base64_encode(s) -> str:
    return base64.urlsafe_b64encode(s).rstrip(b"=").decode("utf-8")


def base64_decode(s) -> str:
    # infer padding
    padding = '=' * (4 - (len(s) % 4))
    return base64.urlsafe_b64decode(s + padding).decode("utf-8")


def generate_salt(nr_bytes=16) -> str:
    return base64_encode(os.urandom(nr_bytes))


def generate_salt_aux(json_path) -> str:
    if USE_EBIP_EXAMPLE:
        TEST_SALT = {
            "$.credentialSubject.familyName": "2GLC42sKQveCfGfryNRN9w",
            "$.credentialSubject.givenName": "eluV5Og3gSNII8EYnsxA_A",
            "$.type": "6Ij7tM-a5iVPGboS5tmvVA",
        }
        return TEST_SALT[json_path]
    return generate_salt()


def remove_path(in_json: Any, keys: List[str]) -> object:
    if not keys:
        raise RuntimeError("empty keys")
    key = keys[0]
    value = in_json[key]
    if len(keys) == 1:
        del in_json[key]
        return value
    else:
        return remove_path(value, keys[1:])


def escape_quotes(obj: object) -> object:
    if isinstance(obj, str):
        return obj.replace('"', '\"')
    elif isinstance(obj, dict):
        return {escape_quotes(k): escape_quotes(v) for k, v in obj.items()}
    else:
        return obj


def get_digest(calculated_disclosure):
    return base64_encode(hashlib.sha256(calculated_disclosure.encode()).digest())


def process(in_json: dict) -> Tuple[dict, list, list]:
    json_paths = [
        "$.credentialSubject.familyName",
        "$.credentialSubject.givenName",
        "$.type",
    ]
    digests = []
    disclosures = []
    for json_path in json_paths:
        salt = generate_salt_aux(json_path)
        keys = json_path.lstrip("$.").split(".")
        value = remove_path(in_json, keys)
        content = str([salt, json_path, escape_quotes(value)]).replace("'", '"')
        print(f"Content: {content}")
        calculated_disclosure = base64_encode(content.encode("utf-8"))
        print(f"calculated Disclosure: {calculated_disclosure}")
        digest = get_digest(calculated_disclosure)
        print(f"calculated Digest: {digest}")
        digests.append(digest)
        disclosures.append((calculated_disclosure, digest, salt, json_path, value))
    in_json["_sd"] = digests
    in_json["_sd_alg"] = "sha-256"

    print("======== Selected content removed ================")
    print(json.dumps(in_json, indent=4))
    print()
    print("Disclosures:")
    print(json.dumps(disclosures, indent=4))
    print()

    return in_json, digests, disclosures


def issue(sd_json, disclosures) -> dict:
    payload_and_signature = jws.sign(sd_json, TEST_KEY, algorithm=ALG)
    header = {"typ": "JWT", "alg": ALG, "b64": False, "crit": ["b64"]}
    protected = base64_encode(to_compact_json(header).encode())
    print("======== Issuance ================")
    payload = str(
        {"sd": payload_and_signature, "disclosures": [x[0] for x in disclosures]}
    ).replace("'", '\"')
    signed_payload = jws.sign(payload.encode(), TEST_KEY, algorithm=ALG)
    flat_json = {
        "signature": signed_payload[signed_payload.rfind(".")+1:],
        "payload": payload,
        "protected": protected,
    }
    print(json.dumps(flat_json, indent=4))
    print()
    return flat_json


def present(flat_json: dict):
    print(f"===== Presentation ==============")
    json_payload = json.loads(flat_json["payload"])
    sd = json_payload["sd"]
    print("sd:", sd)
    disclosures = json_payload["disclosures"]

    for disclosure_index in range(0, len(disclosures)):
        print(f"===== Presentation of disclosure {disclosure_index} ==============")
        disclosure = disclosures[disclosure_index]
        print("providing disclosure:", disclosure)
        disclosure_digest = get_digest(disclosure)
        decoded_jwt = jwt.decode(json_payload["sd"], key=TEST_KEY)
        verified = decoded_jwt["_sd"][disclosure_index] == disclosure_digest
        print("verified:", verified)
        print("decoded:", base64_decode(disclosure))


def main():
    with open("input.json") as in_file:
        contents = in_file.read()
        in_json = json.loads(contents)
        print("======== Before ================")
        print(json.dumps(in_json, indent=4))
        print()
        sd_json, digests, disclosures = process(in_json)
        flat_json = issue(sd_json, disclosures)
        present(flat_json)


if __name__ == '__main__':
    main()
