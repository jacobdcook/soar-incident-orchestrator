from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Union

from fastapi import HTTPException

from models import Alert, Severity


def _first_present(obj: Mapping[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in obj and obj[k] not in (None, "", []):
            return obj[k]
    return None


def _normalize_severity(raw: Optional[Union[str, int]]) -> Severity:
    if raw is None:
        return Severity.MEDIUM
    s = raw if isinstance(raw, str) else str(raw)
    u = s.upper().replace("SEVERITY_", "")
    if u == "CRITICAL":
        return Severity.CRITICAL
    if u == "HIGH":
        return Severity.HIGH
    if u == "MEDIUM":
        return Severity.MEDIUM
    if u in ("LOW", "INFORMATIONAL", "INFO"):
        return Severity.LOW
    if u == "UNKNOWN":
        return Severity.MEDIUM
    return Severity.MEDIUM


def _coalesce_security_blocks(raw: Any) -> List[Dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    return []


def _extract_ip(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, str):
        return val.strip() or None
    if isinstance(val, list):
        for item in val:
            got = _extract_ip(item)
            if got:
                return got
        return None
    if isinstance(val, dict):
        for k in ("ip", "addr", "address"):
            inner = val.get(k)
            if isinstance(inner, str) and inner.strip():
                return inner.strip()
        return None
    return None


def _ip_from_udm(udm: Dict[str, Any]) -> Optional[str]:
    principal = udm.get("principal") if isinstance(udm.get("principal"), dict) else {}
    network = udm.get("network") if isinstance(udm.get("network"), dict) else {}
    target = udm.get("target") if isinstance(udm.get("target"), dict) else {}
    for blk in (
        principal,
        target,
        network,
    ):
        for key in (
            "ip",
            "asset_ip_address",
            "assetNatIpAddress",
            "external_ip_address",
            "internal_ip_address",
            "parsed_ip_address",
            "private_ip_address",
            "public_ip_address",
        ):
            if key not in blk:
                continue
            got = _extract_ip(blk.get(key))
            if got:
                return got
        for nk in ("source_ip", "sourceIp", "destination_ip", "destinationIp"):
            if nk in blk:
                got = _extract_ip(blk.get(nk))
                if got:
                    return got
    return None


def _principal_user(udm: Dict[str, Any]) -> Optional[str]:
    principal = udm.get("principal")
    if not isinstance(principal, dict):
        return None
    user = principal.get("user")
    if not isinstance(user, dict):
        return None
    for k in ("userid", "userId", "email_addresses", "emailAddresses"):
        v = user.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, list) and v and isinstance(v[0], str):
            return v[0].strip()
    return None


def _parse_ts(ts: Any) -> datetime:
    if ts is None:
        return datetime.utcnow()
    if isinstance(ts, (int, float)):
        try:
            if ts > 1e12:
                ts = ts / 1000.0
            return datetime.utcfromtimestamp(ts)
        except (OSError, OverflowError, ValueError):
            return datetime.utcnow()
    if isinstance(ts, str):
        s = ts.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return datetime.utcnow()
    return datetime.utcnow()


def _unwrap_outer(payload: Any) -> Dict[str, Any]:
    if isinstance(payload, list):
        if not payload:
            raise HTTPException(status_code=422, detail="Empty Chronicle payload list")
        payload = payload[0]
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="Chronicle payload must be a JSON object")
    for wrap in ("udm", "event", "message", "jsonPayload"):
        inner = payload.get(wrap)
        if isinstance(inner, dict):
            payload = inner
            break
    for batch in ("events", "records", "messages"):
        items = payload.get(batch)
        if isinstance(items, list) and items:
            first = items[0]
            if isinstance(first, dict):
                if "udm" in first and isinstance(first["udm"], dict):
                    return first["udm"]
                return first
            break
    return payload


def chronicle_udm_to_alert(udm_like: Mapping[str, Any]) -> Alert:
    udm = dict(udm_like)
    metadata = udm.get("metadata") if isinstance(udm.get("metadata"), dict) else {}
    sr_list = []
    sr_raw = _first_present(udm, "security_result", "securityResult")
    sr_list.extend(_coalesce_security_blocks(sr_raw))
    primary = sr_list[0] if sr_list else {}
    severity = _normalize_severity(
        _first_present(primary, "severity", "priority")
        or _first_present(metadata, "severity", "Severity")
    )
    threat = _first_present(primary, "threat_name", "threatName", "rule_name", "ruleName")
    category = _first_present(primary, "category", "Category")
    meta_et = _first_present(metadata, "event_type", "eventType")
    summary = (
        _first_present(primary, "summary", "Summary", "description", "rule_description")
        or _first_present(metadata, "description", "product_log_id")
        or ""
    )
    pieces = [p for p in (threat, category, meta_et) if isinstance(p, str) and p.strip()]
    event_type = pieces[0] if pieces else "Chronicle Security Alert"

    lowered = summary.lower()
    if "brute" in lowered or "credential stuffing" in lowered:
        event_type = f"Authentication Failure Spike - {event_type}"
    ts = _parse_ts(
        _first_present(metadata, "event_timestamp", "eventTimestamp", "ingestion_timestamp", "ingestionTimestamp")
        or datetime.utcnow()
    )
    vendor = _first_present(metadata, "vendor_name", "vendorName")
    product = _first_present(metadata, "product_name", "productName")
    sid = primary.get("detection_rule_id") or primary.get("rule_id") or primary.get("ruleName")
    md: Dict[str, Any] = {"parser": "chronicle_udm", "rule_name": threat, "category": category}
    if vendor:
        md["vendor"] = vendor
    if product:
        md["product"] = product
    if sid:
        md["detection_ref"] = sid
    md = {k: v for k, v in md.items() if v not in (None, "", [])}

    alert = Alert(
        source=_first_present(metadata, "namespace_name", "namespaceName") or "Google Chronicle SecOps",
        event_type=str(event_type)[:500],
        description=(summary.strip() if isinstance(summary, str) else str(summary))[:4000],
        severity=severity,
        source_ip=_ip_from_udm(udm),
        user_id=_principal_user(udm),
        metadata=md,
        timestamp=ts,
    )
    return alert


def parse_chronicle_webhook(payload: Mapping[str, Any]) -> Alert:
    udm = _unwrap_outer(payload)
    meta_ok = isinstance(udm.get("metadata"), dict) and bool(udm.get("metadata"))
    sr_ok = bool(_coalesce_security_blocks(_first_present(udm, "security_result", "securityResult")))
    pr_ok = isinstance(udm.get("principal"), dict) and bool(udm.get("principal"))
    if not (meta_ok or sr_ok or pr_ok):
        raise HTTPException(
            status_code=422,
            detail="Payload is not Chronicle UDM: expected metadata, security_result, or principal",
        )
    try:
        return chronicle_udm_to_alert(udm)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not normalize Chronicle UDM: {exc}") from exc
