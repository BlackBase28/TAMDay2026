.PHONY: run test build

run:
	flask --app wsgi:app run --host 0.0.0.0 --port 8000 --debug

test:
	python -m unittest discover -s tests -p '*_test.py' -v

build:
	podman build -t localhost/kernel-cve-radar:latest .
