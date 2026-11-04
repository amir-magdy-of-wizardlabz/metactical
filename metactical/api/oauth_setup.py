# Copyright (c) 2026, Metactical and contributors
# One-off setup: register the OAuth client the desktop Time Tracker signs in with.
#
# Run against a site, e.g.:
#   bench --site erp.localhost execute \
#     metactical.api.oauth_setup.ensure_timetracker_client
#
# It prints the client_id and client_secret to paste into the agent's config
# (dev.local.json: oauthClientId / oauthClientSecret). The worker never sees
# these; they authenticate through the normal ERP login via OAuth.

import frappe

APP_NAME = "Metactical Time Tracker"
# Fixed loopback redirect; must match oauthRedirectPort in the agent config.
REDIRECT_URI = "http://127.0.0.1:53682/callback"
SCOPES = "all openid"


def ensure_timetracker_client():
	existing = frappe.db.exists("OAuth Client", {"app_name": APP_NAME})
	if existing:
		doc = frappe.get_doc("OAuth Client", existing)
	else:
		doc = frappe.new_doc("OAuth Client")
		doc.app_name = APP_NAME

	doc.scopes = SCOPES
	doc.redirect_uris = REDIRECT_URI
	doc.default_redirect_uri = REDIRECT_URI
	doc.grant_type = "Authorization Code"
	doc.response_type = "Code"
	# Auto-approve: skip the extra consent screen for this internal app.
	doc.skip_authorization = 1
	doc.save(ignore_permissions=True)
	frappe.db.commit()

	print("OAuth client ready for the Time Tracker:")
	print(f"  app_name      : {doc.app_name}")
	print(f"  client_id     : {doc.client_id}")
	print(f"  client_secret : {doc.client_secret}")
	print(f"  redirect_uri  : {REDIRECT_URI}")
	print(f"  scopes        : {SCOPES}")
	print("")
	print("Put these in dev.local.json:")
	print(f'  "oauthClientId": "{doc.client_id}",')
	print(f'  "oauthClientSecret": "{doc.client_secret}"')

	return {"client_id": doc.client_id, "client_secret": doc.client_secret}
