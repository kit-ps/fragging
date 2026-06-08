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
        g++ \
        texlive dvipng texlive-latex-extra texlive-fonts-recommended cm-super


RUN mkdir /root/src &&\
    cd /root/src &&\
    git clone https://github.com/shadow/shadow.git &&\
    cd shadow &&\
    git checkout b814c58bef5488038a4566617aaca20c2549f67c &&\
    ./setup build --clean &&\
    ./setup install

RUN echo 'export PATH="/root/.local/bin:$PATH"' >>/root/.bashrc

WORKDIR /fragging
