# Semgrep rule tests for devsecops-flask-debug-enabled
import os

from flask import Flask

app = Flask(__name__)

# ruleid: devsecops-flask-debug-enabled
app.run(debug=True)

# ruleid: devsecops-flask-debug-enabled
app.run(host="127.0.0.1", port=5000, debug=True)

# ruleid: devsecops-flask-debug-enabled
app.debug = True

# ok: devsecops-flask-debug-enabled
app.run(debug=False)

# ok: devsecops-flask-debug-enabled
app.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")

# ok: devsecops-flask-debug-enabled
app.run(host="127.0.0.1", port=5000)


class Other:
    def run(self, debug=False):
        return debug


other = Other()
# not a Flask application object
# ok: devsecops-flask-debug-enabled
other.run(debug=True)
