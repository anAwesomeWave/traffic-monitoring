FROM python:3.10

WORKDIR /prom-client

COPY requirements.txt .

RUN pip3 install -r requirements.txt --no-cache-dir

COPY . .

CMD ["gunicorn", "-b", "0.0.0.0:5000", "web_app:app", "--log-level", "debug", "--timeout", "600"]