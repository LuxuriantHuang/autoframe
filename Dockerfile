## syntax=docker/dockerfile:1.7
ARG UBUNTU_VERSION=20.04
ARG LLVM_DEFAULT_VERSION=10
ARG LLVM_EXTRA_VERSIONS="18"
ARG REPO_URL=https://github.com/LuxuriantHuang/autoframe.git
ARG REPO_REF=
ARG AFL_REPO_URL=https://github.com/LuxuriantHuang/AFLplusplus.git
ARG AFL_REPO_REF=modified

FROM ubuntu:${UBUNTU_VERSION} AS builder

ARG LLVM_DEFAULT_VERSION
ARG LLVM_EXTRA_VERSIONS
ARG REPO_URL
ARG REPO_REF
ARG AFL_REPO_URL
ARG AFL_REPO_REF

ENV DEBIAN_FRONTEND=noninteractive
ENV AF_HOME=/app
ENV LLVM_APT_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/llvm-apt
ENV PY311_HOME=/opt/py311
ENV PATH=${PY311_HOME}/bin:/usr/lib/llvm-${LLVM_DEFAULT_VERSION}/bin:/app/tools/bin:/root/.local/bin:${PATH}
ENV CC=clang-${LLVM_DEFAULT_VERSION}
ENV CXX=clang++-${LLVM_DEFAULT_VERSION}
ENV LLVM_CONFIG=llvm-config-${LLVM_DEFAULT_VERSION}

WORKDIR /app

RUN printf '%s\n' \
    'deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal main restricted universe multiverse' \
    'deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-updates main restricted universe multiverse' \
    'deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-backports main restricted universe multiverse' \
    'deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-security main restricted universe multiverse' \
    > /etc/apt/sources.list \
    && apt-get update && apt-get install -y --no-install-recommends \
    apt-transport-https \
    autoconf \
    automake \
    bash \
    bear \
    bison \
    build-essential \
    ca-certificates \
    cargo \
    cmake \
    curl \
    file \
    flex \
    g++ \
    gcc \
    gettext \
    git \
    gnupg \
    libedit-dev \
    libffi-dev \
    libncurses5-dev \
    libstdc++6 \
    libtinfo-dev \
    libtool \
    lsb-release \
    make \
    ninja-build \
    pkg-config \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    rustc \
    software-properties-common \
    unzip \
    wget \
    zlib1g-dev

RUN curl -fsSL ${LLVM_APT_MIRROR}/llvm.sh -o /tmp/llvm.sh \
    && chmod +x /tmp/llvm.sh \
    && for version in ${LLVM_EXTRA_VERSIONS} ${LLVM_DEFAULT_VERSION}; do /tmp/llvm.sh "${version}" -m "${LLVM_APT_MIRROR}"; done \
    && rm -f /tmp/llvm.sh

RUN curl --retry 10 --retry-delay 5 -fL https://mirrors.tuna.tsinghua.edu.cn/anaconda/miniconda/Miniconda3-latest-Linux-x86_64.sh -o /tmp/miniforge.sh \
    && bash /tmp/miniforge.sh -b -p /opt/conda \
    && rm -f /tmp/miniforge.sh \
    && /opt/conda/bin/conda config --system --add pkgs_dirs /root/.conda/pkgs \
    && /opt/conda/bin/conda config --system --set remote_max_retries 10 \
    && /opt/conda/bin/conda config --system --set remote_connect_timeout_secs 30 \
    && /opt/conda/bin/conda config --system --set remote_read_timeout_secs 300 \
    && /opt/conda/bin/conda create -y -p ${PY311_HOME} \
      --override-channels \
      -c https://mirrors.tuna.tsinghua.edu.cn/anaconda/pkgs/main \
      python=3.11 pip \
    && printf '%s\n' "${PY311_HOME}/lib" > /etc/ld.so.conf.d/py311.conf \
    && ldconfig \
    && /opt/conda/bin/conda clean -afy

RUN git config --global url."https://github.com/".insteadOf git@github.com: \
    && git clone "${REPO_URL}" /app \
    && cd /app \
    && if [ -n "${REPO_REF}" ]; then \
         git fetch origin "${REPO_REF}" --depth 1 || true; \
         git checkout "${REPO_REF}" || git checkout FETCH_HEAD; \
       fi \
    && git submodule sync --recursive \
    && git submodule update --init --recursive \
      AutoBug \
      ipl-modeling \
      tracer \
      svf/third_party/SVF \
    && rm -rf /app/AFLplusplus \
    && git clone "${AFL_REPO_URL}" /app/AFLplusplus \
    && cd /app/AFLplusplus \
    && if [ -n "${AFL_REPO_REF}" ]; then \
         git fetch origin "${AFL_REPO_REF}" --depth 1 || true; \
         git checkout "${AFL_REPO_REF}" || git checkout FETCH_HEAD; \
       fi

COPY third_party/ipl-libcxx-artifacts/build_fast /app/ipl-modeling/libcxx/build_fast/
COPY third_party/ipl-libcxx-artifacts/build_track /app/ipl-modeling/libcxx/build_track/

COPY scripts/build-third-party.sh /app/scripts/build-third-party.sh

RUN ln -sf ${PY311_HOME}/bin/python /usr/local/bin/python \
    && ln -sf ${PY311_HOME}/bin/python /usr/local/bin/python3 \
    && ln -sf ${PY311_HOME}/bin/pip /usr/local/bin/pip \
    && ln -sf ${PY311_HOME}/bin/pip /usr/local/bin/pip3 \
    && ln -sf /usr/bin/clang-${LLVM_DEFAULT_VERSION} /usr/local/bin/clang \
    && ln -sf /usr/bin/clang++-${LLVM_DEFAULT_VERSION} /usr/local/bin/clang++ \
    && ln -sf /usr/bin/llvm-config-${LLVM_DEFAULT_VERSION} /usr/local/bin/llvm-config \
    && python -m pip install \
      -i https://pypi.tuna.tsinghua.edu.cn/simple \
      --trusted-host pypi.tuna.tsinghua.edu.cn \
      gllvm

RUN python -m pip install \
      -i https://pypi.tuna.tsinghua.edu.cn/simple \
      --trusted-host pypi.tuna.tsinghua.edu.cn \
      -r requirements.txt \
    && python -m pip install \
      -i https://pypi.tuna.tsinghua.edu.cn/simple \
      --trusted-host pypi.tuna.tsinghua.edu.cn \
      -r tracer/requirements.txt

RUN chmod +x scripts/bootstrap-third-party.sh benchmarks/build_single_dir.sh \
    && mkdir -p /app/tools/bin

RUN bash /app/scripts/build-third-party.sh --component all

RUN bash -lc 'set -euo pipefail; \
    mkdir -p /opt/autoframe-runtime/{AFLplusplus,AutoBug,flag_var/flagrec,ipl-modeling,svf,tracer,opt}; \
    cp -a /app/*.py /opt/autoframe-runtime/; \
    cp -a /app/requirements.txt /app/README.md /app/.env.example /opt/autoframe-runtime/; \
    cp -a /app/Excep /app/LLM /app/breaker /app/integrations /app/kaitai /app/pyTracer /app/scripts /app/semantic_fields /app/tools /opt/autoframe-runtime/; \
    cp -a /app/AFLplusplus /opt/autoframe-runtime/; \
    cp -a /app/AutoBug/autobug /opt/autoframe-runtime/AutoBug/; \
    cp -a /app/flag_var/flagrec/build /opt/autoframe-runtime/flag_var/flagrec/; \
    cp -a /app/ipl-modeling/install /opt/autoframe-runtime/ipl-modeling/; \
    cp -a /app/svf/build /app/svf/scripts /opt/autoframe-runtime/svf/; \
    cp -a /app/tracer/build /opt/autoframe-runtime/tracer/; \
    cp -a /opt/conda /opt/autoframe-runtime/opt/; \
    cp -a ${PY311_HOME} /opt/autoframe-runtime/opt/; \
    mkdir -p /opt/autoframe-runtime/benchmarks'

FROM ubuntu:${UBUNTU_VERSION} AS runtime

ARG LLVM_DEFAULT_VERSION
ARG LLVM_EXTRA_VERSIONS

ENV DEBIAN_FRONTEND=noninteractive
ENV AF_HOME=/app
ENV LLVM_APT_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/llvm-apt
ENV PY311_HOME=/opt/py311
ENV PATH=${PY311_HOME}/bin:/usr/lib/llvm-${LLVM_DEFAULT_VERSION}/bin:/app/tools/bin:/root/.local/bin:${PATH}
ENV CC=clang-${LLVM_DEFAULT_VERSION}
ENV CXX=clang++-${LLVM_DEFAULT_VERSION}
ENV LLVM_CONFIG=llvm-config-${LLVM_DEFAULT_VERSION}

WORKDIR /app

RUN printf '%s\n' \
    'deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal main restricted universe multiverse' \
    'deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-updates main restricted universe multiverse' \
    'deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-backports main restricted universe multiverse' \
    'deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ focal-security main restricted universe multiverse' \
    > /etc/apt/sources.list \
    && apt-get update && apt-get install -y --no-install-recommends \
    apt-transport-https \
    bash \
    ca-certificates \
    curl \
    file \
    gnupg \
    libstdc++6 \
    lsb-release \
    python3 \
    python3-pip \
    software-properties-common \
    zlib1g

RUN curl -fsSL ${LLVM_APT_MIRROR}/llvm.sh -o /tmp/llvm.sh \
    && chmod +x /tmp/llvm.sh \
    && for version in ${LLVM_EXTRA_VERSIONS} ${LLVM_DEFAULT_VERSION}; do /tmp/llvm.sh "${version}" -m "${LLVM_APT_MIRROR}"; done \
    && rm -f /tmp/llvm.sh

COPY --from=builder /opt/autoframe-runtime/opt/conda /opt/conda/
COPY --from=builder /opt/autoframe-runtime/opt/py311 /opt/py311/

RUN ln -sf ${PY311_HOME}/bin/python /usr/local/bin/python \
    && ln -sf ${PY311_HOME}/bin/python /usr/local/bin/python3 \
    && ln -sf ${PY311_HOME}/bin/pip /usr/local/bin/pip \
    && ln -sf ${PY311_HOME}/bin/pip /usr/local/bin/pip3 \
    && ln -sf /usr/bin/clang-${LLVM_DEFAULT_VERSION} /usr/local/bin/clang \
    && ln -sf /usr/bin/clang++-${LLVM_DEFAULT_VERSION} /usr/local/bin/clang++ \
    && ln -sf /usr/bin/llvm-config-${LLVM_DEFAULT_VERSION} /usr/local/bin/llvm-config \
    && printf '%s\n' "${PY311_HOME}/lib" > /etc/ld.so.conf.d/py311.conf \
    && ldconfig

COPY --from=builder /opt/autoframe-runtime/ /app/

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    build-essential \
    cmake \
    g++ \
    gcc \
    libtool \
    make \
    ninja-build \
    pkg-config \
    wget \
    && rm -rf /var/lib/apt/lists/* \
    && wget https://ftp.gnu.org/gnu/autoconf/autoconf-2.71.tar.gz \
    && tar -xzf autoconf-2.71.tar.gz \
    && cd autoconf-2.71 \
    && ./configure --prefix=/usr/local \
    && make -j$(nproc) \
    && make install \
    && cd .. \
    && rm -rf autoconf-2.71 autoconf-2.71.tar.gz \
    && wget https://ftp.gnu.org/gnu/automake/automake-1.16.3.tar.gz \
    && tar -xzf automake-1.16.3.tar.gz \
    && cd automake-1.16.3 \
    && ./configure --prefix=/usr/local \
    && make -j$(nproc) \
    && make install \
    && cd .. \
    && rm -rf automake-1.16.3 automake-1.16.3.tar.gz

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# 默认启动：可通过 docker run -e AFL_CMD="..." 传入 AFL 命令
# 或者在容器内手动运行 /app/entrypoint.sh
CMD ["/app/entrypoint.sh"]
