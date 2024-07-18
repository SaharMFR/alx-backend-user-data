#!/usr/bin/env python3
""" Flask app """
from flask import Flask, jsonify

app = Flask(__name__)


@app.route('/', strict_slashes=False)
def start() -> str:
    """ GET /
    Return:
      - start
    """
    return jsonify({"message": "Bienvenue"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
