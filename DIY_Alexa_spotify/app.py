
import os
import time
import secrets
import hmac
from urllib.parse import urlencode

import requests
from flask import (
    Flask, session, redirect, url_for,
    request, jsonify, render_template_string
)
from flask_session import Session
from requests.auth import HTTPBasicAuth

app = Flask(__name__)

# Set these as environment variables on Render.
CLIENT_ID = os.environ.get("SPOTIFY_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("SPOTIFY_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("SPOTIFY_REDIRECT_URI", "")
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "")

if not SECRET_KEY:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is missing")

app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_TYPE="filesystem",
    SESSION_FILE_DIR="/tmp/diy_alexa_sessions",
    SESSION_PERMANENT=False,
    SESSION_USE_SIGNER=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("RENDER") == "true",
)

Session(app)

AUTH_URL = "https://accounts.spotify.com/authorize"
TOKEN_URL = "https://accounts.spotify.com/api/token"
RECENT_URL = (
    "https://api.spotify.com/v1/me/player/recently-played"
)

SCOPES = "user-read-recently-played"


def require_spotify_config():
    if not CLIENT_ID or not CLIENT_SECRET or not REDIRECT_URI:
        raise RuntimeError(
            "Set SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET "
            "and SPOTIFY_REDIRECT_URI"
        )


def spotify_token_request(data):
    """Exchange an authorization code or refresh a token."""
    response = requests.post(
        TOKEN_URL,
        data=data,
        auth=HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET),
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def get_access_token():
    """Return a valid access token, refreshing it when necessary."""
    token = session.get("spotify_token")
    if not token:
        return None

    if time.time() < token["expires_at"] - 60:
        return token["access_token"]

    refresh_token = token.get("refresh_token")
    if not refresh_token:
        session.pop("spotify_token", None)
        return None

    try:
        updated = spotify_token_request({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        })
    except requests.RequestException:
        session.pop("spotify_token", None)
        return None

    token["access_token"] = updated["access_token"]
    token["expires_at"] = time.time() + updated["expires_in"]

    # Spotify may return a new refresh token.
    if updated.get("refresh_token"):
        token["refresh_token"] = updated["refresh_token"]

    session["spotify_token"] = token
    session.modified = True
    return token["access_token"]


@app.get("/")
def home():
    return """
    <h1>DIY Alexa Music Link</h1>
    <p>Connect Spotify, then tap the NFC link to identify your
    most recently played song.</p>
    <p><a href="/login">Connect Spotify</a></p>
    <p><a href="/tap">Identify last-played track</a></p>
    """


@app.get("/login")
def login():
    require_spotify_config()

    # Protect the OAuth callback against forged requests.
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "state": state,
    }

    return redirect(AUTH_URL + "?" + urlencode(params))


@app.get("/callback")
def callback():
    require_spotify_config()

    if request.args.get("error"):
        return "Spotify authorisation was cancelled or denied.", 400

    returned_state = request.args.get("state", "")
    expected_state = session.pop("oauth_state", "")

    if (
        not expected_state
        or not returned_state
        or not hmac.compare_digest(returned_state, expected_state)
    ):
        return "Invalid OAuth state. Please try again from /login.", 400

    code = request.args.get("code")
    if not code:
        return "Spotify did not return an authorisation code.", 400

    try:
        data = spotify_token_request({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        })
    except requests.RequestException:
        app.logger.exception("Spotify token exchange failed")
        return "Could not exchange the Spotify authorisation code.", 502

    session["spotify_token"] = {
        "access_token": data["access_token"],
        "refresh_token": data.get("refresh_token"),
        "expires_at": time.time() + data["expires_in"],
    }

    return redirect(url_for("tap"))


def fetch_last_track():
    access_token = get_access_token()
    if not access_token:
        return None, "Connect Spotify first."

    try:
        response = requests.get(
            RECENT_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            params={"limit": 1},
            timeout=15,
        )
    except requests.RequestException:
        app.logger.exception("Spotify recent-track request failed")
        return None, "Could not reach Spotify. Please try again."

    if response.status_code == 401:
        session.pop("spotify_token", None)
        return None, "Spotify login expired. Connect Spotify again."

    if response.status_code == 403:
        return None, (
            "Spotify denied access. Check your app settings, "
            "account access and API permissions."
        )

    if response.status_code == 429:
        return None, "Spotify rate limit reached. Please wait and retry."

    if not response.ok:
        app.logger.error(
            "Spotify API error: %s", response.status_code
        )
        return None, "Spotify could not return the track."

    items = response.json().get("items", [])
    if not items:
        return None, "Spotify has no recently played track to return."

    entry = items[0]
    track = entry.get("track") or {}
    artists = track.get("artists", [])

    return {
        "name": track.get("name", "Unknown track"),
        "artists": ", ".join(
            artist.get("name", "") for artist in artists
        ),
        "spotify_uri": track.get("uri"),
        "spotify_url": track.get("external_urls", {}).get("spotify"),
        "played_at": entry.get("played_at"),
    }, None


@app.get("/tap")
def tap():
    # On first use, connect Spotify in this browser.
    if not session.get("spotify_token"):
        return redirect(url_for("login"))

    track, error = fetch_last_track()

    if error:
        return render_template_string("""
            <h1>DIY Alexa Music Link</h1>
            <p>{{ error }}</p>
            <p><a href="/login">Connect/reconnect Spotify</a></p>
        """, error=error), 400

    return render_template_string("""
        <h1>Track identified!</h1>
        <h2>{{ track.name }}</h2>
        <p>Artist: {{ track.artists }}</p>
        <p>Last played: {{ track.played_at }}</p>
        <p>
          Spotify URI:
          <code>{{ track.spotify_uri }}</code>
        </p>
        {% if track.spotify_url %}
          <p><a href="{{ track.spotify_url }}">Open track in Spotify</a></p>
        {% endif %}
        <p>This is track identification only. The Pi playback
        controller will be added separately.</p>
        <p><a href="/tap">Check again</a></p>
    """, track=track)


@app.get("/api/last-track")
def api_last_track():
    """Return track metadata for a future authenticated Pi client."""
    if not session.get("spotify_token"):
        return jsonify({"error": "Connect Spotify at /login first"}), 401

    track, error = fetch_last_track()
    if error:
        return jsonify({"error": error}), 400

    return jsonify(track)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # Local development only. Render uses Gunicorn.
    app.run(host="127.0.0.1", port=5000, debug=False)
