FROM rust

RUN apt update &&\
    apt install -y linux-cpupower \
        virtualenv \
        python-is-python3 \
        cmake \
        findutils \
        libclang-dev \
        libc-dbg \
        libglib2.0-0 \
        libglib2.0-dev \
        make \
        netbase \
        python3 \
        python3-networkx \
        xz-utils \
        util-linux \
        gcc \
        g++


RUN mkdir /root/src &&\
    cd /root/src &&\
    git clone https://github.com/shadow/shadow.git &&\
    cd shadow &&\
    git checkout 8442689a2 &&\
    ./setup build --clean &&\
    ./setup install

RUN echo 'export PATH="/root/.local/bin:$PATH"' >>/root/.bashrc

WORKDIR /fragging
