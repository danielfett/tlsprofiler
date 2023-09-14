FROM python:3.7-buster

WORKDIR /usr/src

ADD . /usr/src/tlsprofiler

WORKDIR /usr/src/tlsprofiler

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "run.py"]
