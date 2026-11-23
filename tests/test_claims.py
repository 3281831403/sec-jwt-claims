"""Fixed acceptance tests for the JWT claim-validation exercise.

These tests describe the intended secure behavior.  Only ``jwtc/claims.py``
may be changed; this file must not be modified, skipped, or shortened.
"""

import base64
import hashlib
import hmac
import json

import pytest

from jwtc.claims import (
    check_audience,
    check_issuer,
    check_time,
    claims_batch,
    split_token,
    validate_claims,
    validate_policy,
    verify_signature,
)

KEY = b"gsb-jwt-claims-2026"
HEADER = {"alg": "HS256", "typ": "JWT"}


def _canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _segment(value):
    return _b64url(_canonical_json(value))


def _signature(header, payload, key=KEY, digest=hashlib.sha256):
    signing_input = (_segment(header) + "." + _segment(payload)).encode("ascii")
    return hmac.new(key, signing_input, digest).digest()


def _token(header, payload, key=KEY, digest=hashlib.sha256):
    signature = _signature(header, payload, key, digest)
    return _segment(header) + "." + _segment(payload) + "." + _b64url(signature)


def _payload(**overrides):
    payload = {
        "iss": "auth-a",
        "aud": "tenant-a",
        "nbf": 1000,
        "exp": 2000,
    }
    payload.update(overrides)
    return payload


def _policy(**overrides):
    policy = {
        "algorithms": ["HS256"],
        "max_skew": 30,
        "audience": "tenant-a",
        "issuers": ["auth-a"],
        "key": KEY,
    }
    policy.update(overrides)
    return policy


def test_defect_01_split_rejects_wrong_segment_count():
    with pytest.raises(ValueError):
        split_token("header.payload")
    with pytest.raises(ValueError):
        split_token("header.payload.signature.extra")


def test_defect_02_split_decodes_base64url_segments():
    payload = _payload(pad="???")
    token = _token(HEADER, payload)
    assert "_" in token.split(".")[1]

    header, decoded, signature = split_token(token)
    assert header == HEADER
    assert decoded == payload
    assert signature == _signature(HEADER, payload)


def test_defect_03_signature_uses_fixed_algorithm_whitelist():
    header = {"alg": "HS512", "typ": "JWT"}
    payload = _payload()
    signature = _signature(header, payload, digest=hashlib.sha512)

    assert verify_signature(header, payload, signature, KEY) is False


def test_defect_04_signature_rejects_none_algorithm():
    assert verify_signature({"alg": "none"}, _payload(), b"", KEY) is False
    assert verify_signature({"typ": "JWT"}, _payload(), b"", KEY) is False


def test_defect_05_time_rejects_not_yet_valid_token():
    payload = _payload(nbf=2000, exp=3000)

    assert check_time(payload, 1999, 0) is False
    assert check_time(payload, 2000, 0) is True
    assert check_time(payload, 2999, 0) is True


def test_defect_06_time_skew_is_applied_once_and_capped():
    payload = _payload(nbf=1000, exp=2000)

    assert check_time(payload, 2029, 30) is True
    assert check_time(payload, 2030, 30) is False
    assert check_time(payload, 2059, 30) is False
    assert check_time(payload, 970, 30) is True
    assert check_time(payload, 969, 30) is False

    with pytest.raises(ValueError):
        check_time(payload, 1500, 61)

    issues = validate_policy(
        {
            "algorithms": [],
            "max_skew": 3600,
            "audience": "",
            "issuers": ["auth-a"],
        }
    )
    assert issues == [
        "algorithm_unrestricted",
        "skew_excessive",
        "audience_empty",
    ]


def test_defect_07_audience_checks_entire_array():
    payload = {"aud": ["tenant-b", "tenant-a"]}

    assert check_audience(payload, "tenant-a") is True
    assert check_audience({"aud": ["tenant-b"]}, "tenant-a") is False
    assert check_audience({"aud": "tenant-a"}, "tenant-a") is True
    assert check_audience({"aud": "tenant-a-extra"}, "tenant-a") is False


def test_defect_08_issuer_requires_exact_match():
    allowed = ["auth-a"]

    assert check_issuer({"iss": "auth-a"}, allowed) is True
    assert check_issuer({"iss": "auth-a-extra"}, allowed) is False
    assert check_issuer({"iss": "auth"}, allowed) is False


def test_defect_09_claims_report_each_failed_check():
    payload = _payload(exp=900, aud="tenant-b", iss="auth-b")

    result = validate_claims(payload, _policy(), 1000)

    assert result == {
        "time": False,
        "audience": False,
        "issuer": False,
        "valid": False,
    }


def test_defect_10_batch_isolates_audience_between_tokens():
    first = _token(HEADER, _payload(aud="tenant-a"))
    second = _token(HEADER, _payload(aud="tenant-b", exp=2100))

    result = claims_batch([first, second], _policy(), 1500)

    assert result[first]["audience"] is True
    assert result[first]["valid"] is True
    assert result[second]["audience"] is False
    assert result[second]["valid"] is False


def test_valid_token_passes_all_checks():
    policy = _policy()
    token = _token(HEADER, _payload())

    header, payload, signature = split_token(token)

    assert verify_signature(header, payload, signature, policy["key"]) is True
    assert check_time(payload, 1500, policy["max_skew"]) is True
    assert check_audience(payload, policy["audience"]) is True
    assert check_issuer(payload, policy["issuers"]) is True
    assert validate_claims(payload, policy, 1500) == {
        "time": True,
        "audience": True,
        "issuer": True,
        "valid": True,
    }
    assert validate_policy(policy) == []
    assert claims_batch([token], policy, 1500) == {
        token: {
            "signature": True,
            "time": True,
            "audience": True,
            "issuer": True,
            "valid": True,
        }
    }


def test_tampered_payload_fails_signature():
    token = _token(HEADER, _payload())
    header, payload, signature = split_token(token)

    assert verify_signature(header, payload, signature, KEY) is True

    tampered = dict(payload)
    tampered["exp"] = 2600
    assert verify_signature(header, tampered, signature, KEY) is False


def test_expired_token_is_rejected():
    policy = _policy(max_skew=0)
    payload = _payload(exp=1500)

    assert check_time(payload, 1499, 0) is True
    assert check_time(payload, 1500, 0) is False
    assert validate_claims(payload, policy, 1500)["time"] is False


def test_audience_mismatch_is_rejected():
    assert check_audience({"aud": "tenant-b"}, "tenant-a") is False
    assert check_audience({"aud": ["tenant-a", "tenant-b"]}, "tenant-c") is False
    assert (
        validate_claims(_payload(aud="tenant-b"), _policy(), 1500)["audience"]
        is False
    )


def test_batches_match_individual_validation():
    policy = _policy()
    now = 1500
    tokens_a = [
        _token(HEADER, _payload()),
        _token(HEADER, _payload(exp=1400)),
    ]
    tokens_b = [
        _token(HEADER, _payload(aud="tenant-b")),
        _token(HEADER, _payload(iss="auth-b")),
    ]

    def individually(tokens):
        results = {}
        for token in tokens:
            header, payload, signature = split_token(token)
            signature_ok = verify_signature(
                header, payload, signature, policy["key"]
            )
            checks = validate_claims(payload, policy, now)
            results[token] = {
                "signature": signature_ok,
                "time": checks["time"],
                "audience": checks["audience"],
                "issuer": checks["issuer"],
                "valid": signature_ok and checks["valid"],
            }
        return results

    assert claims_batch(tokens_a, policy, now) == individually(tokens_a)
    assert claims_batch(tokens_b, policy, now) == individually(tokens_b)
