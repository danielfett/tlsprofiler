FROM debian:10.2

WORKDIR /usr/src/tlsprofiler

COPY requirements.txt ./
RUN apt update && apt install -y libssl-dev python3 python3-pip
RUN apt install -y git build-essential
RUN apt install -y openssl
RUN pip3 install requests && pip3 install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT [ "python3", "/usr/src/tlsprofiler/tlsprofiler/__init__.py" ]