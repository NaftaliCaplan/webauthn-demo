import os, sqlite3, dataclasses, enum, json
from datetime import datetime
from hashlib import sha256
from flask import Flask, request, session, jsonify, send_file
from webauthn import (generate_registration_options, verify_registration_response,
                      generate_authentication_options, verify_authentication_response, options_to_json)
from webauthn.helpers import (bytes_to_base64url, base64url_to_bytes, parse_client_data_json,
                              parse_attestation_object, parse_authenticator_data, decode_credential_public_key,
                              parse_registration_credential_json, parse_authentication_credential_json)
from webauthn.helpers.structs import AuthenticatorSelectionCriteria, ResidentKeyRequirement

RP_ID, RP_NAME, ORIGIN = "localhost", "WebAuthn Demo", "http://localhost:5000"

app = Flask(__name__)
app.secret_key = "cy2550-demo-key"  # fixed so logins survive server restarts (fine for a demo, never in production)

def db():
    conn = sqlite3.connect(os.path.join(app.root_path, "webauthn.db"))  # next to app.py, whatever the working dir
    conn.execute("CREATE TABLE IF NOT EXISTS credentials (id BLOB PRIMARY KEY, username TEXT, public_key BLOB, sign_count INTEGER, transports TEXT)")
    return conn

def j(x):
    """Make library structs JSON-friendly so the page can display them (bytes shown as hex)."""
    if dataclasses.is_dataclass(x): return {f.name: j(getattr(x, f.name)) for f in dataclasses.fields(x)}
    if isinstance(x, dict): return {str(k): j(v) for k, v in x.items()}
    if isinstance(x, list): return [j(v) for v in x]
    if isinstance(x, bytes): return x.hex()
    if isinstance(x, enum.Enum): return x.value
    return x

def decode_client_data(raw):
    return {"raw": raw.decode(), "parsed": json.loads(raw)}

def decode_auth_data(ad):
    out = {"rpIdHash": ad.rp_id_hash.hex(), "flags": j(ad.flags), "signCount": ad.sign_count}
    if ad.attested_credential_data:
        acd = ad.attested_credential_data
        out["attestedCredentialData"] = {
            "aaguid": acd.aaguid.hex(),
            "credentialId (base64url)": bytes_to_base64url(acd.credential_id),
            "credentialPublicKey (COSE)": j(decode_credential_public_key(acd.credential_public_key)),
        }
    return out

def common_checks(client, ad, expected_type, expected_challenge):
    return [
        [f"clientData.type is '{expected_type}'", j(client.type) == expected_type],
        ["clientData.challenge matches the challenge saved in the session", client.challenge == expected_challenge],
        [f"clientData.origin is '{ORIGIN}'", client.origin == ORIGIN],
        [f"authData.rpIdHash == SHA-256('{RP_ID}')", ad.rp_id_hash == sha256(RP_ID.encode()).digest()],
        ["User Present (UP) flag is set", ad.flags.up],
    ]

@app.get("/")
def index():
    return send_file("index.html")

@app.get("/me")
def me():
    return jsonify(user=session.get("user"), since=session.get("since"))

@app.get("/users")
def users():
    with db() as conn:
        rows = conn.execute("SELECT username, sign_count, transports FROM credentials ORDER BY rowid").fetchall()
    return jsonify([{"username": u, "sign_count": c, "transports": json.loads(t)} for u, c, t in rows])

@app.delete("/users/<username>")
def delete_user(username):
    with db() as conn:
        ids = [bytes_to_base64url(r[0]) for r in conn.execute("SELECT id FROM credentials WHERE username = ?", (username,))]
        conn.execute("DELETE FROM credentials WHERE username = ?", (username,))
    if session.get("user") == username:
        session.pop("user"), session.pop("since", None)
    return jsonify(ok=True, deleted=ids)  # credential IDs, so the page can tell the browser to forget them

@app.post("/logout")
def logout():
    session.pop("since", None)
    return jsonify(ok=True, was=session.pop("user", None))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":  # step 1: send creation options to the browser
        if session.get("user"):
            return jsonify(ok=False, error=f"Logged in as '{session['user']}'. Log out before registering a new user."), 409
        username = request.args["username"]
        with db() as conn:
            if conn.execute("SELECT 1 FROM credentials WHERE username = ?", (username,)).fetchone():
                return jsonify(ok=False, error=f"'{username}' is already registered. Pick another username."), 409
        opts = generate_registration_options(rp_id=RP_ID, rp_name=RP_NAME, user_name=username,
                                             user_id=username.encode(),
                                             # any authenticator (this device, a phone, a security key), but it must
                                             # make a discoverable passkey because login sends an empty allowCredentials
                                             authenticator_selection=AuthenticatorSelectionCriteria(
                                                 resident_key=ResidentKeyRequirement.REQUIRED))
        session["challenge"], session["pending_user"] = bytes_to_base64url(opts.challenge), username
        return options_to_json(opts)

    # step 2: decode + verify the authenticator's response, then store the credential
    if "challenge" not in session:
        return jsonify(ok=False, error="No registration in progress (challenge missing)"), 400
    challenge = base64url_to_bytes(session.pop("challenge"))
    cred = parse_registration_credential_json(request.get_json())
    client = parse_client_data_json(cred.response.client_data_json)
    att = parse_attestation_object(cred.response.attestation_object)
    decoded = {"clientDataJSON": decode_client_data(cred.response.client_data_json),
               "attestationObject": {"fmt": att.fmt, "attStmt": j(att.att_stmt), "authData": decode_auth_data(att.auth_data)}}
    checks = common_checks(client, att.auth_data, "webauthn.create", challenge)
    checks.append(["Attested credential data (AT) flag is set: a new public key is included", att.auth_data.flags.at])
    try:
        v = verify_registration_response(credential=cred, expected_challenge=challenge,
                                         expected_rp_id=RP_ID, expected_origin=ORIGIN)
    except Exception as e:
        checks.append(["verify_registration_response()", False])
        return jsonify(ok=False, error=str(e), decoded=decoded, checks=checks), 400
    checks.append([f"Attestation statement (fmt='{v.fmt}') is valid; verify_registration_response() passed", True])
    username, transports = session["pending_user"], [t.value for t in cred.response.transports or []]
    with db() as conn:
        conn.execute("INSERT INTO credentials VALUES (?, ?, ?, ?, ?)",
                     (v.credential_id, username, v.credential_public_key, v.sign_count, json.dumps(transports)))
    stored = {"id": bytes_to_base64url(v.credential_id), "username": username,
              "public_key": v.credential_public_key.hex(), "sign_count": v.sign_count, "transports": transports}
    return jsonify(ok=True, decoded=decoded, checks=checks, stored=stored,
                   info={"user_verified": v.user_verified, "device_type": v.credential_device_type.value,
                         "backed_up": v.credential_backed_up})

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":  # step 1: send a challenge for this user's credentials
        if session.get("user"):
            return jsonify(ok=False, error=f"Already logged in as '{session['user']}'. Log out first."), 409
        username = request.args.get("username", "")
        if username:
            with db() as conn:
                if not conn.execute("SELECT 1 FROM credentials WHERE username = ?", (username,)).fetchone():
                    return jsonify(ok=False, error=f"No passkeys registered for '{username}'"), 404
        # allowCredentials is left EMPTY even when we know the username. In Edge, naming specific credentials routes
        # the request through Windows back into Microsoft Password Manager, and that path fails the first attempt
        # every time. With an empty list, Edge shows its own passkey picker and signs directly. The POST step then
        # checks that the chosen passkey really belongs to this username.
        opts = generate_authentication_options(rp_id=RP_ID)
        session["challenge"], session["pending_user"] = bytes_to_base64url(opts.challenge), username or None
        return options_to_json(opts)

    # step 2: decode + verify the signature against the stored public key
    if "challenge" not in session:
        return jsonify(ok=False, error="No login in progress (challenge missing)"), 400
    challenge, username = base64url_to_bytes(session.pop("challenge")), session["pending_user"]
    cred = parse_authentication_credential_json(request.get_json())
    client = parse_client_data_json(cred.response.client_data_json)
    ad = parse_authenticator_data(cred.response.authenticator_data)
    decoded = {"clientDataJSON": decode_client_data(cred.response.client_data_json),
               "authenticatorData": decode_auth_data(ad),
               "signature": cred.response.signature.hex(),
               "userHandle": cred.response.user_handle.decode() if cred.response.user_handle else None}
    checks = common_checks(client, ad, "webauthn.get", challenge)
    with db() as conn:
        row = conn.execute("SELECT public_key, sign_count, username FROM credentials WHERE id = ?", (cred.raw_id,)).fetchone()
        if username:
            ok = bool(row) and row[2] == username
            checks.append([f"Credential ID is registered to '{username}' in SQLite", ok])
        else:  # usernameless: the passkey itself tells us who the user is
            ok = bool(row)
            checks.append([f"Credential ID found in SQLite, belongs to '{row[2]}'" if row else
                           "Credential ID is in SQLite: no, this passkey is not in the database (probably a leftover from earlier testing)", ok])
        if not ok:
            error = f"You picked the passkey for '{row[2]}', not '{username}'" if row else "Unknown credential"
            return jsonify(ok=False, error=error, unknown=not row, decoded=decoded, checks=checks), 400
        username = row[2]
        try:
            v = verify_authentication_response(credential=cred, expected_challenge=challenge,
                                               expected_rp_id=RP_ID, expected_origin=ORIGIN,
                                               credential_public_key=row[0], credential_current_sign_count=row[1])
        except Exception as e:
            checks.append(["Signature valid over authenticatorData || SHA-256(clientDataJSON)", False])
            return jsonify(ok=False, error=str(e), decoded=decoded, checks=checks), 400
        checks.append(["Signature valid over authenticatorData || SHA-256(clientDataJSON) using stored public key", True])
        checks.append([f"Sign count OK (stored {row[1]} → received {v.new_sign_count})", True])
        conn.execute("UPDATE credentials SET sign_count = ? WHERE id = ?", (v.new_sign_count, v.credential_id))
    session["user"], session["since"] = username, datetime.now().strftime("%H:%M:%S")
    return jsonify(ok=True, user=username, decoded=decoded, checks=checks,
                   info={"user_verified": v.user_verified, "new_sign_count": v.new_sign_count})

if __name__ == "__main__":
    app.run(host="localhost", port=5000)
