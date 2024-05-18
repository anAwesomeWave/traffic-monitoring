FROM python:3.10

WORKDIR /prom-client

COPY requirements.txt .

RUN pip3 install -r requirements.txt --no-cache-dir

COPY . .

CMD ["uwsgi", "--http", "0.0.0.0:5000", "--wsgi-file", "web_app.py", "--callable", "app"]