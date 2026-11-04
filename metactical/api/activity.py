# Copyright (c) 2026, Metactical and contributors
# Time-tracker activity ingestion: per-session key exchange, signed interval
# uploads with integrity + replay protection, and authoritative scoring.

import hashlib
import hmac
import json
import secrets

import frappe
from frappe.utils import now_datetime, get_datetime, get_system_timezone

try:
	from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
	ZoneInfo = None

# --- Scoring (authoritative; mirror of the client preview in score.js) ---
MAX_KEYSTROKES = 600
MAX_CLICKS = 300
KEY_WEIGHT = 0.6
CLICK_WEIGHT = 0.4

# --- Integrity guards ---
TIMESTAMP_SKEW_SECONDS = 900   # reject intervals timestamped >15 min from server time
DEFAULT_WINDOW_MINUTES = 10


def _score(keystrokes, mouse_clicks):
	key_max = frappe.db.get_single_value(
		"Time Tracker Settings", "max_keystrokes_per_interval"
	) or MAX_KEYSTROKES
	click_max = frappe.db.get_single_value(
		"Time Tracker Settings", "max_clicks_per_interval"
	) or MAX_CLICKS
	k_norm = min((keystrokes or 0) / key_max, 1.0)
	c_norm = min((mouse_clicks or 0) / click_max, 1.0)
	return round((KEY_WEIGHT * k_norm + CLICK_WEIGHT * c_norm) * 100)


def _canonical(payload):
	"""Rebuild the exact string the agent signed (see signing.js:canonicalString)."""
	shots = ",".join(
		f"{s.get('monitor')}:{s.get('sha256')}" for s in payload.get("screenshots", [])
	)
	parts = [
		payload.get("session_id"),
		payload.get("interval_start"),
		payload.get("interval_end"),
		payload.get("keystrokes"),
		payload.get("mouse_clicks"),
		payload.get("nonce"),
		payload.get("timestamp"),
		shots,
	]
	return "|".join("" if p is None else str(p) for p in parts)


def _open_clockin_log(user):
	return frappe.db.exists("Clockin Log", {"user": user, "has_clocked_out": 0})


@frappe.whitelist()
def start_tracking_session():
	"""Issue a per-session HMAC key bound to the user's open Clockin Log."""
	user = frappe.session.user
	clockin_log = _open_clockin_log(user)
	if not clockin_log:
		frappe.throw("No open clock-in found. Clock in before starting tracking.")

	# Reuse an already-active session for this clock-in if one exists.
	existing = frappe.db.exists(
		"Tracking Session", {"clockin_log": clockin_log, "status": "Active"}
	)
	if existing:
		doc = frappe.get_doc("Tracking Session", existing)
		key = doc.get_password("session_key")
	else:
		key = secrets.token_hex(32)
		window = (
			frappe.db.get_single_value("Time Tracker Settings", "window_minutes")
			or DEFAULT_WINDOW_MINUTES
		)
		doc = frappe.get_doc(
			{
				"doctype": "Tracking Session",
				"user": user,
				"clockin_log": clockin_log,
				"status": "Active",
				"window_minutes": window,
				"started_on": now_datetime(),
				"session_key": key,
			}
		)
		doc.insert(ignore_permissions=True)
		frappe.db.commit()

	return {
		"session_id": doc.name,
		"session_key": key,
		"window_minutes": doc.window_minutes or DEFAULT_WINDOW_MINUTES,
	}


@frappe.whitelist()
def end_tracking_session(session_id):
	user = frappe.session.user
	doc = frappe.get_doc("Tracking Session", session_id)
	if doc.user != user:
		frappe.throw("Not your session.", frappe.PermissionError)
	doc.status = "Ended"
	doc.ended_on = now_datetime()
	doc.save(ignore_permissions=True)
	frappe.db.commit()
	return {"ended": 1}


def _verify_and_load_session(payload):
	user = frappe.session.user
	session_id = payload.get("session_id")
	if not session_id:
		frappe.throw("Missing session_id.")
	session = frappe.get_doc("Tracking Session", session_id)
	if session.user != user:
		frappe.throw("Session does not belong to the authenticated user.", frappe.PermissionError)
	if session.status != "Active":
		frappe.throw("Tracking session is not active.")
	return session


def _parse_client_datetime(value):
	"""Parse an ISO-8601 timestamp from the agent into a naive datetime in the
	site timezone, the convention Frappe uses everywhere (now_datetime() and
	Datetime fields are naive site-local). The agent sends UTC with a trailing
	"Z", which get_datetime() returns as an aware datetime; subtracting that
	from now_datetime() raises TypeError, so normalise here."""
	dt = get_datetime(value)
	if dt is None:
		raise ValueError("empty datetime")
	if dt.tzinfo is not None:
		if ZoneInfo is not None:
			dt = dt.astimezone(ZoneInfo(get_system_timezone()))
		else:
			import pytz
			dt = dt.astimezone(pytz.timezone(get_system_timezone()))
		dt = dt.replace(tzinfo=None)
	return dt


def _check_freshness_and_replay(session, payload):
	# Freshness: reject stale or future-dated payloads.
	try:
		ts = _parse_client_datetime(payload.get("timestamp"))
	except Exception:
		frappe.throw("Invalid timestamp.")
	skew = abs((now_datetime() - ts).total_seconds())
	if skew > TIMESTAMP_SKEW_SECONDS:
		frappe.throw("Payload timestamp outside the allowed window.")

	# Replay: a nonce may be used at most once per session.
	nonce = payload.get("nonce")
	if not nonce:
		frappe.throw("Missing nonce.")
	if frappe.db.exists("Activity Interval", {"session": session.name, "nonce": nonce}):
		frappe.throw("Duplicate interval (nonce already used).")


def _verify_signature(session, payload):
	expected = payload.get("signature")
	if not expected:
		frappe.throw("Missing signature.")
	key = session.get_password("session_key")
	computed = hmac.new(
		key.encode("utf-8"), _canonical(payload).encode("utf-8"), hashlib.sha256
	).hexdigest()
	if not hmac.compare_digest(computed, expected):
		frappe.throw("Signature verification failed.", frappe.PermissionError)


def _read_verified_files(payload):
	"""Match each signed screenshot to its uploaded file and verify bytes."""
	files = frappe.request.files
	verified = []
	for shot in payload.get("screenshots", []):
		monitor = shot.get("monitor")
		field = f"shot_{monitor}"
		if field not in files:
			frappe.throw(f"Missing uploaded file for monitor {monitor}.")
		content = files[field].stream.read()
		digest = hashlib.sha256(content).hexdigest()
		if digest != shot.get("sha256"):
			frappe.throw(f"Screenshot hash mismatch for monitor {monitor}.", frappe.PermissionError)
		verified.append(
			{
				"monitor": monitor,
				"content": content,
				"sha256": digest,
				"width": shot.get("width") or 0,
				"height": shot.get("height") or 0,
			}
		)
	return verified


@frappe.whitelist()
def submit_interval():
	"""Ingest one signed interval with its per-monitor screenshots.

	Expects multipart form-data:
	  - payload : JSON (session_id, interval_start, interval_end, keystrokes,
	              mouse_clicks, nonce, timestamp, signature, screenshots[])
	  - shot_<monitor> : the JPEG bytes for each monitor in screenshots[]
	"""
	raw = frappe.form_dict.get("payload")
	if not raw:
		frappe.throw("Missing payload.")
	payload = json.loads(raw)

	session = _verify_and_load_session(payload)
	_check_freshness_and_replay(session, payload)
	_verify_signature(session, payload)
	verified_files = _read_verified_files(payload)

	try:
		start = _parse_client_datetime(payload.get("interval_start"))
		end = _parse_client_datetime(payload.get("interval_end"))
	except Exception:
		frappe.throw("Invalid interval_start / interval_end.")
	duration = round((end - start).total_seconds() / 60.0, 2) if start and end else 0
	keystrokes = int(payload.get("keystrokes") or 0)
	mouse_clicks = int(payload.get("mouse_clicks") or 0)

	doc = frappe.get_doc(
		{
			"doctype": "Activity Interval",
			"session": session.name,
			"clockin_log": session.clockin_log,
			"user": session.user,
			"interval_start": start,
			"interval_end": end,
			"duration_mins": duration,
			"keystrokes": keystrokes,
			"mouse_clicks": mouse_clicks,
			"activity_score": _score(keystrokes, mouse_clicks),
			"monitor_count": len(verified_files),
			"nonce": payload.get("nonce"),
			"signature_valid": 1,
			"screenshots": [
				{
					"monitor": f["monitor"],
					"sha256": f["sha256"],
					"width": f["width"],
					"height": f["height"],
				}
				for f in verified_files
			],
		}
	)
	doc.insert(ignore_permissions=True)

	# Persist each verified image as a private File attached to this interval.
	by_monitor = {f["monitor"]: f for f in verified_files}
	for row in doc.screenshots:
		f = by_monitor.get(row.monitor)
		if not f:
			continue
		_file = frappe.get_doc(
			{
				"doctype": "File",
				"file_name": f"{doc.name}_m{row.monitor}.jpg",
				"attached_to_doctype": "Activity Interval",
				"attached_to_name": doc.name,
				"content": f["content"],
				"is_private": 1,
			}
		)
		_file.save(ignore_permissions=True)
		row.image = _file.file_url

	doc.save(ignore_permissions=True)
	frappe.db.commit()

	return {
		"ok": 1,
		"interval": doc.name,
		"activity_score": doc.activity_score,
		"monitors": doc.monitor_count,
	}
