import random
import time

from flask import Flask, request
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from prometheus_client import make_wsgi_app, Summary
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, \
    REGISTRY
from prometheus_client.registry import Collector
from flask_json import FlaskJSON, JsonError, json_response, as_json

# Create my app

app = Flask(__name__)
json = FlaskJSON(app)
# app.config['JSON_AS_ASCII'] = False
# json.provider.DefaultJSONProvider.ensure_ascii = False
app.json.ensure_ascii = False

my_val = 1.7


class CustomCollector(Collector):
    my_metrics = {
        'number_of_http_packets': 0
    }

    def collect(self):
        yield GaugeMetricFamily('my_gauge', 'Help text', value=7)
        c = CounterMetricFamily('my_counter_total', 'Help text',
                                labels=['foo'])
        c.add_metric(['bar'], my_val)
        c.add_metric(['baz'], 3.8)
        for k, v in self.my_metrics.items():
            c.add_metric([k], v)
        if my_val > 5:
            c.add_metric(['yahuy'], 1200)
        yield c


REGISTRY.register(CustomCollector())


@app.route('/get_data', methods=['POST'])
@as_json
def get_data():
    """
        нужно название, сама метрика, хелп текст и как показывать
    """
    data = request.get_json(force=True)

    for key in data.keys():
        if key not in CustomCollector.my_metrics:
            raise JsonError(
                description=f"key '{key}' not present in {list(CustomCollector.my_metrics.keys())}"
            )
        CustomCollector.my_metrics[key] = data[key]

    return {
        'ok': 'success',
        'description': 'Ты красавчик-контрибьютор. Все хорошо!'
    }


app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {
    '/metrics': make_wsgi_app(REGISTRY)
})

if __name__ == '__main__':
    app.run(debug=True)
