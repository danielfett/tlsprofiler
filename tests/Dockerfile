FROM python:3.7-buster

RUN apt update && apt install -y git

WORKDIR /usr/src

RUN git clone https://github.com/fabian-hk/nassl.git

WORKDIR /usr/src/nassl

RUN git checkout tls_profiler

RUN pip install mypy flake8 pytest twine invoke requests black==19.3b0

RUN invoke build.all

RUN pip wheel . -w wheelhouse/

RUN pip install wheelhouse/nassl-2.2.0-cp37-cp37m-linux_x86_64.whl

WORKDIR /usr/src/tlsprofiler

COPY requirements.txt ./

RUN pip install requests
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD python -m unittest tests/profile_tests.py tests/function_tests.py
