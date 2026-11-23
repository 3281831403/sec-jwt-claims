"""Offline JWT claim-validation exercise with explicit clocks.

The module models a compact JWS token with three dot-separated segments.
Every function is deterministic: callers pass the validation time explicitly,
no function reads the system clock, and no randomness is used.  The baseline
clock tolerance is 0 seconds and the largest permitted tolerance is 60
seconds.  Only HS256 is accepted for signatures.

Signing input used by :func:`verify_signature` is::

    base64url(canonical_json(header)) + "." + base64url(canonical_json(payload))

where canonical JSON is UTF-8 encoded with sorted keys, separators set to a
comma and a colon, no extra whitespace, and ``ensure_ascii=False``.
Base64URL output is unpadded and uses the URL-safe alphabet.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import string
from collections.abc import Mapping

ALLOWED_ALGORITHMS = frozenset({"HS256"})
MAX_CLOCK_SKEW = 60

_B64URL_CHARS = frozenset(
    string.ascii_letters + string.digits + "-_"
)

_MISSING = object()


def _b64url_encode(raw: bytes) -> str:
    """Encode bytes as unpadded Base64URL text."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_segment(segment: str, name: str) -> bytes:
    """Strictly decode one unpadded Base64URL segment.

    Rejects empty input, padding, any character outside the URL-safe
    alphabet, impossible lengths, and non-canonical trailing bits.
    """
    if not segment:
        raise ValueError(f"empty {name} segment")
    for char in segment:
        if char not in _B64URL_CHARS:
            raise ValueError(f"invalid character in {name} segment")
    if len(segment) % 4 == 1:
        raise ValueError(f"impossible length for {name} segment")

    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid {name} segment") from exc

    if _b64url_encode(raw) != segment:
        # Non-canonical trailing bits or an otherwise repairable segment.
        raise ValueError(f"non-canonical {name} segment")
    return raw


def _decode_json_object(raw: bytes, name: str) -> dict:
    """Decode a UTF-8 JSON object from one segment's bytes."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{name} segment is not valid UTF-8") from exc
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{name} segment is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{name} segment is not a JSON object")
    return value


def _is_int(value) -> bool:
    """Return True for a genuine integer (booleans excluded)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _normalise_key(key) -> bytes:
    """Return the HMAC key as bytes, rejecting unsupported types."""
    if isinstance(key, bytes):
        return key
    if isinstance(key, str):
        return key.encode("utf-8")
    raise TypeError("key must be bytes or a string")


def _signing_input(header, payload) -> bytes:
    """Build the canonical HS256 signing input for a header/payload pair."""
    header_text = _b64url_encode(
        json.dumps(
            header,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    )
    payload_text = _b64url_encode(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    )
    return (header_text + "." + payload_text).encode("ascii")


def split_token(token: str) -> tuple:
    """Split a compact token into decoded header, payload, and signature.

    Contract:
        A token is valid only when it is a string containing exactly three
        non-empty segments separated by single dots.  Zero, one, two, or more
        than three segments are malformed.  Leading or trailing dots and
        empty segments are malformed.

        Each segment is Base64URL encoded with the URL-safe alphabet, using
        ``-`` and ``_`` instead of ``+`` and ``/``.  Padding is not present
        in the token and a literal ``=`` is rejected.  Characters outside the
        Base64URL alphabet, impossible lengths, and invalid trailing bits are
        rejected.  The first two decoded segments must be UTF-8 JSON objects;
        they are returned as dicts.  The third segment is decoded to raw
        signature bytes and is not interpreted here.

        This function never repairs a malformed token and never accepts a
        two-segment or unsigned token.  It raises ``ValueError`` for any
        format, alphabet, UTF-8, JSON, or shape problem, and ``TypeError``
        when ``token`` is not a string.

    Args:
        token: Compact token text.

    Returns:
        A tuple ``(header, payload, signature)`` where the first two items
        are dicts and the third item is bytes.

    Raises:
        ValueError: If the token is not exactly three well-formed segments
            carrying two JSON objects.
        TypeError: If ``token`` is not a string.
    """
    if not isinstance(token, str):
        raise TypeError("token must be a string")

    segments = token.split(".")
    if len(segments) != 3:
        raise ValueError("token must contain exactly three segments")
    if not all(segments):
        raise ValueError("token contains an empty segment")

    header_raw = _decode_segment(segments[0], "header")
    payload_raw = _decode_segment(segments[1], "payload")
    signature = _decode_segment(segments[2], "signature")

    header = _decode_json_object(header_raw, "header")
    payload = _decode_json_object(payload_raw, "payload")
    return header, payload, signature


def verify_signature(header: dict, payload: dict, signature: bytes, key) -> bool:
    """Verify an HS256 signature against a fixed algorithm allowlist.

    Contract:
        ``header`` and ``payload`` are mappings as returned by
        :func:`split_token`.  ``signature`` is the raw decoded signature
        bytes.  ``key`` is the HMAC secret as bytes or as a string encoded to
        UTF-8.

        The algorithm is selected by this function, never by the token.  The
        header field ``alg`` must be present and exactly equal to ``HS256``;
        the values ``none``, ``HS384``, ``HS512``, mixed case, missing values,
        and non-string values all return ``False`` before any HMAC is
        computed.  The allowlist is fixed at HS256 and is not taken from a
        policy or from token metadata.

        The expected signature is HMAC-SHA256 over the canonical signing
        input described in the module docstring.  Compare it with
        ``hmac.compare_digest`` and return ``False`` for a mismatch, a wrong
        signature length, or malformed attacker-controlled input.  This
        function does not check claims and does not read a clock.

    Args:
        header: Decoded header mapping.
        payload: Decoded payload mapping.
        signature: Raw signature bytes.
        key: HMAC secret bytes or UTF-8 string.

    Returns:
        ``True`` only for a valid HS256 signature made with ``key``.

    Raises:
        TypeError: If ``key`` is neither bytes nor a string, or if the
            supplied header or payload is not a mapping.
    """
    if not isinstance(header, Mapping):
        raise TypeError("header must be a mapping")
    if not isinstance(payload, Mapping):
        raise TypeError("payload must be a mapping")
    secret = _normalise_key(key)

    # The algorithm is chosen here, never trusted from the token header.
    algorithm = header.get("alg", _MISSING)
    if not isinstance(algorithm, str) or algorithm not in ALLOWED_ALGORITHMS:
        return False

    if not isinstance(signature, (bytes, bytearray)):
        return False
    signature = bytes(signature)

    try:
        message = _signing_input(header, payload)
    except (TypeError, ValueError, UnicodeEncodeError):
        return False

    expected = hmac.new(secret, message, hashlib.sha256).digest()
    if len(signature) != len(expected):
        return False
    return hmac.compare_digest(expected, signature)


def check_time(payload: dict, now: int, skew: int) -> bool:
    """Check the validity window with a bounded one-time clock allowance.

    Contract:
        The payload must contain integer ``nbf`` and ``exp`` values in Unix
        epoch seconds.  Booleans are not accepted as integers.  ``now`` is
        the caller-supplied validation time.  The baseline tolerance is 0
        seconds; ``skew`` is the only allowance and must be an integer from
        0 through 60 inclusive.

        The token is valid exactly when::

            nbf - skew <= now < exp + skew

        Thus ``nbf`` is inclusive at its boundary and ``exp`` is exclusive:
        at ``now == nbf`` the token is valid, at ``now == exp`` it is expired,
        at ``now == nbf - skew`` it is still acceptable, and at
        ``now == exp + skew`` it is expired.  The allowance is applied once
        to each boundary and is never applied twice to the same boundary or
        otherwise doubled.  A missing, non-integer, or inconsistent window
        returns ``False``.

    Args:
        payload: Decoded claim mapping.
        now: Validation time in Unix epoch seconds.
        skew: Permitted clock tolerance in seconds, from 0 to 60.

    Returns:
        ``True`` only when ``now`` lies inside the skewed validity window.

    Raises:
        ValueError: If ``now`` is not an integer, or if ``skew`` is not an
            integer in the closed range 0 through 60.
    """
    if not _is_int(now):
        raise ValueError("now must be an integer")
    if not _is_int(skew) or not 0 <= skew <= MAX_CLOCK_SKEW:
        raise ValueError(f"skew must be an integer from 0 to {MAX_CLOCK_SKEW}")

    if not isinstance(payload, Mapping):
        return False
    nbf = payload.get("nbf", _MISSING)
    exp = payload.get("exp", _MISSING)
    if not _is_int(nbf) or not _is_int(exp):
        return False
    if nbf > exp:
        return False

    # The allowance is applied once to each boundary, never compounded.
    return nbf - skew <= now < exp + skew


def check_audience(payload: dict, expected: str) -> bool:
    """Check that the token audience contains the expected audience.

    Contract:
        ``expected`` must be a non-empty string.  The claim ``aud`` may be a
        string or a non-empty list of non-empty strings.  For a string claim,
        matching is exact equality.  For a list claim, the function returns
        ``True`` when ``expected`` occurs anywhere in the list, not merely at
        index zero.  A missing claim, an empty value, an invalid type, or a
        list containing any invalid member returns ``False``.

        No prefix, suffix, substring, case-insensitive, wildcard, or
        first-element-only matching is permitted.

    Args:
        payload: Decoded claim mapping.
        expected: Audience required by the relying party.

    Returns:
        ``True`` only for an exact audience match, or membership in an
        audience array.

    Raises:
        ValueError: If ``expected`` is not a non-empty string.
    """
    if not isinstance(expected, str) or expected == "":
        raise ValueError("expected audience must be a non-empty string")

    if not isinstance(payload, Mapping):
        return False
    audience = payload.get("aud", _MISSING)

    if isinstance(audience, str):
        return audience != "" and audience == expected

    if isinstance(audience, list):
        if not audience:
            return False
        for member in audience:
            if not isinstance(member, str) or member == "":
                return False
        # Check the whole array, not just its first element.
        return expected in audience

    return False


def check_issuer(payload: dict, allowed) -> bool:
    """Check the issuer against a whitelist using exact equality.

    Contract:
        ``allowed`` is a non-empty collection of issuer strings; a bare
        string is treated as a one-item whitelist.  The claim ``iss`` must be
        a non-empty string that is exactly equal to one of the allowed
        values.  Prefix matching, suffix matching, substring matching, and
        case folding are forbidden: for example, an allowed value of
        ``auth-a`` does not admit ``auth-a-extra`` or ``auth``.

        A missing or invalid issuer claim returns ``False``.  An empty or
        malformed whitelist is a programming error.

    Args:
        payload: Decoded claim mapping.
        allowed: Non-empty issuer string or collection of issuer strings.

    Returns:
        ``True`` only for an exact whitelist match.

    Raises:
        ValueError: If the whitelist is empty or contains a non-string or
            empty issuer.
        TypeError: If ``allowed`` is neither a string nor an iterable of
            strings.
    """
    if isinstance(allowed, str):
        candidates = [allowed]
    elif isinstance(allowed, (bytes, bytearray)):
        raise TypeError("allowed must not be bytes")
    else:
        try:
            candidates = list(allowed)
        except TypeError as exc:
            raise TypeError(
                "allowed must be a string or an iterable of strings"
            ) from exc

    if not candidates:
        raise ValueError("issuer whitelist must not be empty")
    for candidate in candidates:
        if not isinstance(candidate, str) or candidate == "":
            raise ValueError("issuer whitelist contains an invalid entry")

    if not isinstance(payload, Mapping):
        return False
    issuer = payload.get("iss", _MISSING)
    if not isinstance(issuer, str) or issuer == "":
        return False

    # Full-string equality only; no prefix or substring matching.
    return issuer in candidates


def validate_claims(payload: dict, policy: dict, now: int) -> dict:
    """Validate time, audience, and issuer and report every result.

    Contract:
        ``policy`` must contain a valid ``algorithms`` allowlist, a
        ``max_skew`` value from 0 through 60, a non-empty ``audience``, and a
        non-empty ``issuers`` collection.  The policy is checked with
        :func:`validate_policy`; an invalid policy raises ``ValueError``
        rather than producing a partial result.

        The returned mapping has exactly these boolean keys::

            {
                "time": check_time(payload, now, policy["max_skew"]),
                "audience": check_audience(payload, policy["audience"]),
                "issuer": check_issuer(payload, policy["issuers"]),
                "valid": all three checks are true,
            }

        A single failed check must never be swallowed: its key is ``False``
        and ``valid`` is ``False``.  The baseline tolerance is 0 seconds when
        ``max_skew`` is 0.  This function checks claims only; signature and
        algorithm verification are handled by :func:`verify_signature` and
        :func:`claims_batch`.  Inputs are not mutated.

    Args:
        payload: Decoded claim mapping.
        policy: Validation policy mapping.
        now: Validation time in Unix epoch seconds.

    Returns:
        A dict with the four boolean keys described above.

    Raises:
        ValueError: If the policy is not valid or ``now`` is invalid.
        TypeError: If ``policy`` is not a mapping.
    """
    if not isinstance(policy, Mapping):
        raise TypeError("policy must be a mapping")

    issues = validate_policy(policy)
    if issues:
        raise ValueError("invalid policy: " + ", ".join(issues))

    time_ok = check_time(payload, now, policy["max_skew"])
    audience_ok = check_audience(payload, policy["audience"])
    issuer_ok = check_issuer(payload, policy["issuers"])

    # Every individual result is preserved; none is allowed to be swallowed.
    return {
        "time": time_ok,
        "audience": audience_ok,
        "issuer": issuer_ok,
        "valid": bool(time_ok and audience_ok and issuer_ok),
    }


def validate_policy(policy: dict) -> list[str]:
    """Return stable issue codes for security problems in a policy.

    Contract:
        A safe policy has exactly these required fields:

        ``algorithms``
            A non-empty list or tuple of algorithm names.  Only HS256 is
            supported in this exercise.
        ``max_skew``
            An integer from 0 through 60 inclusive.
        ``audience``
            A non-empty string without surrounding-only whitespace.
        ``issuers``
            A non-empty list or tuple of non-empty issuer strings.

        Return an empty list for a safe policy.  Otherwise return issue codes
        in this fixed order, one code per problem:

        ``algorithm_unrestricted``
            ``algorithms`` is missing, not a list or tuple, or empty.
        ``algorithm_not_allowed``
            ``algorithms`` contains a value other than HS256.  This code is
            emitted once even if several unsupported values are present.
        ``skew_invalid``
            ``max_skew`` is missing, not an integer, a boolean, or negative.
        ``skew_excessive``
            ``max_skew`` is greater than 60.
        ``audience_empty``
            ``audience`` is missing, not a string, empty, or whitespace only.
        ``issuer_unrestricted``
            ``issuers`` is missing, not a list or tuple, empty, or contains a
            non-string or empty value.

        ``skew_invalid`` and ``skew_excessive`` are mutually exclusive for a
        particular value.  Unknown policy keys, including a signature key,
        are ignored.  This function reports problems instead of raising for
        bad field values.

    Args:
        policy: Mapping containing the policy fields.

    Returns:
        A list of issue-code strings, empty when the policy is safe.

    Raises:
        TypeError: If ``policy`` is not a mapping.
    """
    if not isinstance(policy, Mapping):
        raise TypeError("policy must be a mapping")

    issues = []

    algorithms = policy.get("algorithms", _MISSING)
    if not isinstance(algorithms, (list, tuple)) or len(algorithms) == 0:
        issues.append("algorithm_unrestricted")
    elif any(algorithm != "HS256" for algorithm in algorithms):
        issues.append("algorithm_not_allowed")

    max_skew = policy.get("max_skew", _MISSING)
    if not _is_int(max_skew) or max_skew < 0:
        issues.append("skew_invalid")
    elif max_skew > MAX_CLOCK_SKEW:
        issues.append("skew_excessive")

    audience = policy.get("audience", _MISSING)
    if not isinstance(audience, str) or audience.strip() == "":
        issues.append("audience_empty")

    issuers = policy.get("issuers", _MISSING)
    if not isinstance(issuers, (list, tuple)) or len(issuers) == 0:
        issues.append("issuer_unrestricted")
    elif any(not isinstance(issuer, str) or issuer == "" for issuer in issuers):
        issues.append("issuer_unrestricted")

    return issues


def claims_batch(tokens, policy: dict, now: int) -> dict:
    """Validate a batch of tokens with no state shared between iterations.

    Contract:
        ``tokens`` is an iterable of compact token strings.  ``policy`` is a
        claim policy as accepted by :func:`validate_claims` and must also
        contain ``key``, the HMAC secret as bytes or a UTF-8 string, used for
        signature verification.  The policy is validated first; an invalid
        policy or a missing key raises ``ValueError``.

        Each token is processed from scratch in input order: split it, verify
        its signature with the fixed HS256 allowlist, and validate its claims
        with the supplied policy and ``now``.  No decoded header, payload,
        signature, audience, or other intermediate value may be reused for a
        later token.

        The result maps each exact token string to exactly::

            {
                "signature": bool,
                "time": bool,
                "audience": bool,
                "issuer": bool,
                "valid": all four checks are true,
            }

        A malformed token maps to all five keys set to ``False`` plus
        ``"error": "malformed"``.  Duplicate token strings are allowed and
        produce the same independent result.  The input order must not change
        any individual result.

    Args:
        tokens: Iterable of compact token strings.
        policy: Claim policy plus the HMAC ``key``.
        now: Validation time in Unix epoch seconds.

    Returns:
        A dict keyed by token string, each value holding per-check booleans.

    Raises:
        ValueError: If the policy is invalid, ``key`` is missing or invalid,
            or ``now`` is invalid.
    """
    if not isinstance(policy, Mapping):
        raise TypeError("policy must be a mapping")

    issues = validate_policy(policy)
    if issues:
        raise ValueError("invalid policy: " + ", ".join(issues))

    key = policy.get("key", _MISSING)
    if key is _MISSING or not isinstance(key, (bytes, str)):
        raise ValueError("policy must contain a bytes or string key")

    if not _is_int(now):
        raise ValueError("now must be an integer")

    results = {}
    for token in tokens:
        # Start every iteration from scratch: no cached header, payload,
        # signature, audience, or claim state carries over between tokens.
        try:
            header, payload, signature = split_token(token)
        except (ValueError, TypeError):
            results[token] = {
                "signature": False,
                "time": False,
                "audience": False,
                "issuer": False,
                "valid": False,
                "error": "malformed",
            }
            continue

        signature_ok = verify_signature(header, payload, signature, key)
        checks = validate_claims(payload, policy, now)

        results[token] = {
            "signature": signature_ok,
            "time": checks["time"],
            "audience": checks["audience"],
            "issuer": checks["issuer"],
            "valid": bool(
                signature_ok
                and checks["time"]
                and checks["audience"]
                and checks["issuer"]
            ),
        }

    return results
