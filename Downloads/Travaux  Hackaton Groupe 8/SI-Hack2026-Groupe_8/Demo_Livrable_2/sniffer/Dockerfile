FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Mise à jour + outils essentiels
RUN apt update && apt install -y \
    bash \
    coreutils \
    util-linux \
    procps \
    iputils-ping \
    net-tools \
    diffutils \
    findutils \
    dnsutils \
    iproute2 \
    man-db \
    nano \
    vim \
    less \
    file \
    grep \
    sed \
    gawk \
    htop \
    btop \
    psmisc \
    hollywood \
    cmatrix \
    sudo \
    tzdata \
    tcpdump \
    mosquitto-clients \
    && apt clean

# Activer man
RUN yes | unminimize

# Historique persistant
RUN echo 'export HISTFILE=/root/.bash_history' >> /root/.bashrc && \
    echo 'export HISTSIZE=10000' >> /root/.bashrc

# Prompt lisible
RUN echo 'PS1="\\u@\\h:\\w\\$ "' >> /root/.bashrc

CMD ["/bin/bash"]
