import json
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
from backend.app.models.models import AuditEvent, AuditOutcome, SecurityEvent

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

def compute_canonical_string(
    sequence_number: int,
    actor_user_id: Optional[str],
    actor_email: str,
    action: str,
    document_id: Optional[str],
    target_user_id: Optional[str],
    timestamp_iso: str,
    outcome: str,
    reason_code: str,
    metadata_json: str,
) -> str:
    try:
        parsed = json.loads(metadata_json or "{}")
        sorted_meta = json.dumps(parsed, sort_keys=True)
    except Exception:
        sorted_meta = "{}"

    parts = [
        str(sequence_number),
        actor_user_id or "null",
        actor_email,
        action,
        document_id or "null",
        target_user_id or "null",
        timestamp_iso,
        outcome,
        reason_code,
        sorted_meta,
    ]
    return "|".join(parts)

def sha256_hex(val: str) -> str:
    return hashlib.sha256(val.encode("utf-8")).hexdigest()

class AuditService:
    @staticmethod
    def record_event(
        db: Session,
        actor_user_id: Optional[str],
        actor_email: str,
        action: str,
        document_id: Optional[str],
        target_user_id: Optional[str],
        outcome: AuditOutcome,
        reason_code: str,
        request_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        # Get latest event in sequence
        last_event = db.query(AuditEvent).order_by(AuditEvent.sequence_number.desc()).first()
        prev_hash = last_event.event_hash if last_event else GENESIS_HASH
        seq_num = (last_event.sequence_number + 1) if last_event else 1

        now_utc = datetime.now(timezone.utc)
        meta_str = json.dumps(metadata or {}, sort_keys=True)

        canonical_str = compute_canonical_string(
            sequence_number=seq_num,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            action=action,
            document_id=document_id,
            target_user_id=target_user_id,
            timestamp_iso=now_utc.isoformat(),
            outcome=outcome.value,
            reason_code=reason_code,
            metadata_json=meta_str,
        )

        canonical_hash = sha256_hex(canonical_str)
        event_hash = sha256_hex(prev_hash + canonical_hash)

        event = AuditEvent(
            id=f"aud_{seq_num}",
            event_id=str(uuid.uuid4()),
            sequence_number=seq_num,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            action=action,
            document_id=document_id,
            target_user_id=target_user_id,
            timestamp=now_utc,
            outcome=outcome,
            reason_code=reason_code,
            request_id=request_id,
            metadata_json=meta_str,
            previous_hash=prev_hash,
            canonical_hash=canonical_hash,
            event_hash=event_hash,
        )

        db.add(event)

        # Log security alert if denied
        if outcome == AuditOutcome.DENIED or action == "UNAUTHORIZED_ACCESS_ATTEMPT":
            sec_event = SecurityEvent(
                id=f"sec_{uuid.uuid4().hex[:8]}",
                event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
                severity="HIGH",
                actor_email=actor_email,
                details=f"Denied action {action} on document {document_id or 'N/A'}. Reason: {reason_code}",
                timestamp=now_utc,
                resolved=False,
            )
            db.add(sec_event)

        db.commit()
        db.refresh(event)
        return event

    @staticmethod
    def verify_chain(db: Session) -> Dict[str, Any]:
        events = db.query(AuditEvent).order_by(AuditEvent.sequence_number.asc()).all()
        if not events:
            return {
                "is_valid": True,
                "total_events": 0,
                "verified_events": 0,
                "tampered_event_id": None,
                "tampered_sequence": None,
                "error_message": None,
                "genesis_hash": GENESIS_HASH,
                "latest_event_hash": GENESIS_HASH,
                "chain_head_timestamp": None,
            }

        expected_prev = GENESIS_HASH

        for idx, evt in enumerate(events):
            expected_seq = idx + 1
            if evt.sequence_number != expected_seq:
                return {
                    "is_valid": False,
                    "total_events": len(events),
                    "verified_events": idx,
                    "tampered_event_id": evt.id,
                    "tampered_sequence": evt.sequence_number,
                    "error_message": f"Sequence discontinuity. Expected {expected_seq}, found {evt.sequence_number}.",
                    "genesis_hash": GENESIS_HASH,
                    "latest_event_hash": events[-1].event_hash,
                    "chain_head_timestamp": events[-1].timestamp,
                }

            if evt.previous_hash != expected_prev:
                return {
                    "is_valid": False,
                    "total_events": len(events),
                    "verified_events": idx,
                    "tampered_event_id": evt.id,
                    "tampered_sequence": evt.sequence_number,
                    "error_message": f"Chain link broken at sequence {evt.sequence_number}. Previous hash mismatch.",
                    "genesis_hash": GENESIS_HASH,
                    "latest_event_hash": events[-1].event_hash,
                    "chain_head_timestamp": events[-1].timestamp,
                }

            recomputed_canonical = compute_canonical_string(
                sequence_number=evt.sequence_number,
                actor_user_id=evt.actor_user_id,
                actor_email=evt.actor_email,
                action=evt.action,
                document_id=evt.document_id,
                target_user_id=evt.target_user_id,
                timestamp_iso=evt.timestamp.isoformat(),
                outcome=evt.outcome.value,
                reason_code=evt.reason_code,
                metadata_json=evt.metadata_json,
            )
            recomputed_canonical_hash = sha256_hex(recomputed_canonical)

            if recomputed_canonical_hash != evt.canonical_hash:
                return {
                    "is_valid": False,
                    "total_events": len(events),
                    "verified_events": idx,
                    "tampered_event_id": evt.id,
                    "tampered_sequence": evt.sequence_number,
                    "error_message": f"Data integrity violation at sequence {evt.sequence_number}. Stored canonical hash mismatch.",
                    "genesis_hash": GENESIS_HASH,
                    "latest_event_hash": events[-1].event_hash,
                    "chain_head_timestamp": events[-1].timestamp,
                }

            recomputed_event_hash = sha256_hex(evt.previous_hash + recomputed_canonical_hash)
            if recomputed_event_hash != evt.event_hash:
                return {
                    "is_valid": False,
                    "total_events": len(events),
                    "verified_events": idx,
                    "tampered_event_id": evt.id,
                    "tampered_sequence": evt.sequence_number,
                    "error_message": f"Event hash check failed at sequence {evt.sequence_number}.",
                    "genesis_hash": GENESIS_HASH,
                    "latest_event_hash": events[-1].event_hash,
                    "chain_head_timestamp": events[-1].timestamp,
                }

            expected_prev = evt.event_hash

        return {
            "is_valid": True,
            "total_events": len(events),
            "verified_events": len(events),
            "tampered_event_id": None,
            "tampered_sequence": None,
            "error_message": None,
            "genesis_hash": GENESIS_HASH,
            "latest_event_hash": events[-1].event_hash,
            "chain_head_timestamp": events[-1].timestamp,
        }
