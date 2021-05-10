web: NEW_RELIC_CONFIG_FILE=newrelic.ini newrelic-admin run-program gunicorn app:app
worker: NEW_RELIC_CONFIG_FILE=newrelic.ini newrelic-admin run-program python listar.py $PROJECT sub_worker
