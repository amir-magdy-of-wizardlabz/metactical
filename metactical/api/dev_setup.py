# Copyright (c) 2026, Metactical and contributors
# DEV ONLY: provision the minimum HR masters so the desktop Time Tracker can
# clock in on a fresh local site. Not for production.
#
#   bench --site erp.localhost execute \
#     metactical.api.dev_setup.ensure_test_timetracker_data

from datetime import date, timedelta

import frappe

SHIFT_NAME = "Tracker Full Day"


def _any_gender():
	for g in ("Male", "Female", "Other"):
		if frappe.db.exists("Gender", g):
			return g
	return frappe.db.get_value("Gender", {}, "name")


def ensure_test_timetracker_data(user="Administrator", company="metactical"):
	# Self-reporting wrapper: bench execute in this build masks exceptions, so
	# we catch, print the real traceback, and return rather than re-raise.
	import traceback
	try:
		return _ensure(user, company)
	except Exception:
		traceback.print_exc()
		return {"error": "see traceback above"}


def _ensure(user, company):
	out = {}

	# 1. Employee linked to the user.
	emp = frappe.db.exists("Employee", {"user_id": user})
	if not emp:
		udoc = frappe.get_doc("User", user)
		employee = frappe.get_doc({
			"doctype": "Employee",
			"first_name": (udoc.first_name or user.split("@")[0] or "Test"),
			"user_id": user,
			"company": company,
			"status": "Active",
			"gender": _any_gender(),
			"date_of_birth": "1990-01-01",
			"date_of_joining": str(date.today() - timedelta(days=365)),
		})
		employee.insert(ignore_permissions=True)
		emp = employee.name
	out["employee"] = emp

	# 2. All-day Shift Type (so "now" is always within the shift window).
	if not frappe.db.exists("Shift Type", SHIFT_NAME):
		frappe.get_doc({
			"doctype": "Shift Type",
			"__newname": SHIFT_NAME,
			"name": SHIFT_NAME,
			# Wide but < 24h window with zero buffers, so hrms does not flag a
			# self-overlapping ("circular") shift.
			"start_time": "00:00:00",
			"end_time": "23:30:00",
			"begin_check_in_before_shift_start_time": 0,
			"allow_check_out_after_shift_end_time": 0,
		}).insert(ignore_permissions=True)
	out["shift_type"] = SHIFT_NAME

	# 3. Active, submitted Shift Assignment.
	sa = frappe.db.exists("Shift Assignment", {"employee": emp, "status": "Active", "docstatus": 1})
	if not sa:
		doc = frappe.get_doc({
			"doctype": "Shift Assignment",
			"employee": emp,
			"shift_type": SHIFT_NAME,
			"company": company,
			"status": "Active",
			"start_date": str(date.today() - timedelta(days=1)),
		})
		doc.insert(ignore_permissions=True)
		doc.submit()
		sa = doc.name
	out["shift_assignment"] = sa

	# 4. Time Tracker Settings: pay cycle covering today + approver + window.
	tts = frappe.get_single("Time Tracker Settings")
	tts.start_date = str(date.today() - timedelta(days=7))
	if not tts.checkin_approver:
		tts.checkin_approver = frappe.db.get_value("User", user, "email") or "admin@example.com"
	if not getattr(tts, "window_minutes", None):
		tts.window_minutes = 2
	tts.save(ignore_permissions=True)
	frappe.db.commit()
	out["pay_cycle_start"] = str(tts.start_date)

	print("Dev time-tracker data ready:")
	for k, v in out.items():
		print(f"  {k:18}: {v}")
	return out
