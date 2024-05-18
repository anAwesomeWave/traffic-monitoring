import random
import time

from flask import Flask, request
from werkzeug.middleware.dispatcher import DispatcherMiddleware

from prometheus_client import make_wsgi_app, Summary, Gauge, Histogram, Counter
import prometheus_client

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

# {'open_hosts', 'Number of open hosts in network', ''}
str_to_class = {
    'Gauge': Gauge,
    'Counter': Counter,
    'Histogram': Histogram,
    'Summary': Summary,
}

my_metrics = {
    # value, object, method of incr.
    'number_of_http_packets': [0, Counter('number_of_http_packets',
                                          'Description'), 'inc'],
}


def process_update():
    for k, v in my_metrics.items():
        getattr(v[1], v[2])(v[0])


@app.route('/create_metrics', methods=['POST'])
@as_json
def create_metrics():
    """
        принимает JSON-массив с метриками, которые нужно добавить.
        Каждая метрика содержит: Название, Описание, Тип из мн-ва {Gauge, ...}

        [
            {"value": , "name": , "class": , "description": , "method": },
            {...}
        ]

        Ex. [{"value": 0, "name": "new", "class": "Counter", "description": "wewqeqwe", "method": "inc"}]


    """
    data = request.get_json(force=True)

    for metric in data:
        my_metrics[metric['name']] = [metric['value'], getattr(prometheus_client, metric['class'])(metric['name'], metric['description']), metric['method']]

@app.route('/get_data', methods=['POST'])
@as_json
def get_data():
    """
        Принимает словарь с обновленными данными по метрикам.

        {
            "metric-1": value-1,
            "metric-2": value-2,
            ...
        }
        все метрики из словаря должны существовать
    """
    data = request.get_json(force=True)

    for key in data.keys():
        if key not in my_metrics:
            raise JsonError(
                description=f"key '{key}' not present in {list(my_metrics.keys())}"
            )
        my_metrics[key][0] = data[key]

    process_update()

    return {
        'ok': 'success',
        'description': 'Ты красавчик-контрибьютор. Все хорошо!'
    }


app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {
    '/metrics': make_wsgi_app()
    # '/metrics': make_wsgi_app(REGISTRY)
})

if __name__ == '__main__':
    app.run(debug=True)
