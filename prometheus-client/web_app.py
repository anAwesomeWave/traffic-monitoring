import random
import time

from flask import Flask
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from prometheus_client import make_wsgi_app, Summary


# Create my app

app = Flask(__name__)

# Add prometheus wsgi middleware to route /metrics requests

REQUEST_TIME = Summary('request_processing_seconds', 'Time spent processing request')

# Decorate function with metric.
@REQUEST_TIME.time()
def process_request(t):
    """A dummy function that takes some time."""
    time.sleep(t)


app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {

    '/metrics': make_wsgi_app()

})

if __name__ == '__main__':
    app.run(debug=True)