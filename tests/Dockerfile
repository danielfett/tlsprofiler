FROM python:3.7-buster

WORKDIR /usr/src/tlsprofiler

COPY requirements.txt ./

RUN pip install requests
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD python -m unittest tests/profile_tests.py tests/function_tests.py
