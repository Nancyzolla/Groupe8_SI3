FROM postgres:15

RUN apt-get update && \
    apt-get install -y mosquitto-clients

RUN mkdir /backup
COPY ./ca.crt /root/ca.crt