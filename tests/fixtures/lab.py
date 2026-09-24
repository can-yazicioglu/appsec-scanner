"""Deliberately vulnerable controlled fixture. Never deploy this service."""

import html
import sqlite3
from contextlib import contextmanager
from threading import Thread

from flask import Flask, jsonify, redirect, request
from werkzeug.serving import make_server


def create_lab():
    app = Flask(__name__)
    app.config["HITS"] = []
    app.config["RESOURCE_USERS"] = []

    @app.before_request
    def count():
        app.config["HITS"].append(request.path)

    @app.get("/")
    def index():
        return '<a href="/xss?q=hello">reflect</a><a href="/sql?id=1">sql</a><form action="/escaped"><input name="q" value="hello"></form>'

    @app.get("/xss")
    def xss():
        return "<html><body>" + request.args.get("q", "") + "</body></html>"

    @app.get("/escaped")
    def escaped():
        return "<html><body>" + html.escape(request.args.get("q", "")) + "</body></html>"

    @app.post("/post-reflect")
    def post_reflect():
        values = request.get_json(silent=True) or request.form
        return "<html><body>" + values.get("q", "") + "</body></html>"

    @app.get("/unrelated")
    def unrelated():
        return '<script>alert("unrelated")</script>' + html.escape(request.args.get("q", ""))

    @app.get("/sql")
    def sql():
        with sqlite3.connect(":memory:") as db:
            db.execute("CREATE TABLE items(id INTEGER, name TEXT)")
            db.execute("INSERT INTO items VALUES(1, 'fixture-item')")
            try:
                rows = db.execute("SELECT name FROM items WHERE id=" + request.args.get("id", "1")).fetchall()
                return jsonify([r[0] for r in rows])
            except sqlite3.Error:
                return "SQLITE_ERROR: fixture query failed", 500

    @app.get("/error-only")
    def error_only():
        return (
            ("SQLITE_ERROR: fixture-only simulated parser error", 500)
            if "'" in request.args.get("q", "")
            else "ordinary response"
        )

    @app.get("/safe")
    def safe():
        return "ordinary response"

    @app.get("/redirect")
    def outside_redirect():
        return redirect(request.args["to"])

    @app.get("/spa")
    def spa():
        return '<html><body><script>fetch("/api/search?q=hello").then(r=>r.json()).then(d=>document.body.dataset.ready="yes")</script></body></html>'

    @app.get("/api/search")
    def api():
        return jsonify({"fixture": True})

    @app.get("/external")
    def external():
        return '<script>fetch("http://localhost:' + request.host.split(":")[-1] + '/outside")</script>'

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return '<form><input name="csrf_token" value="fixture-csrf"></form>'
        values = request.get_json(silent=True) or request.form
        if values.get("username") not in ("alice", "bob") or values.get("password") != "fixture-password":
            return jsonify(error="denied"), 403
        user = values["username"]
        response = jsonify(authentication={"token": "fixture-token-" + user})
        response.set_cookie("session", "fixture-session-" + user, httponly=True)
        return response

    def user():
        cookie, bearer = request.cookies.get("session", ""), request.headers.get("Authorization", "")
        for name in ("alice", "bob"):
            if cookie == "fixture-session-" + name or bearer == "Bearer fixture-token-" + name:
                return name
        return None

    @app.get("/me")
    def me():
        return (jsonify(user=user()), 200) if user() else (jsonify(error="denied"), 401)

    @app.get("/private-xss")
    def private_xss():
        return xss() if user() else ("denied", 401)

    @app.get("/resource/<mode>/<int:item>")
    def resource(mode, item):
        app.config["RESOURCE_USERS"].append(user())
        owner = "alice" if item == 1 else "bob"
        if not user():
            return jsonify(error="denied"), 401
        if mode == "secure" and user() != owner:
            return jsonify(error="forbidden"), 403
        if mode == "login-page" and user() != owner:
            return "<html>Login required</html>"
        return jsonify(id=item, owner=owner, protected="fixture-private-" + owner)

    return app


@contextmanager
def live_lab():
    app = create_lab()
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", app
    finally:
        server.shutdown()
        thread.join(timeout=3)


if __name__ == "__main__":
    create_lab().run(host="127.0.0.1", port=8765, debug=False)
