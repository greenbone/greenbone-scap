FROM debian:stable-slim AS builder

COPY . /source

WORKDIR /source

RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
    python3 \
    python-is-python3 \
    pipx && \
    apt-get remove --purge --auto-remove -y && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install poetry

RUN rm -rf dist && /root/.local/bin/poetry build -f wheel

FROM debian:stable-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PIP_NO_CACHE_DIR off

WORKDIR /greenbone-scap

RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
    gosu \
    python3 \
    python-is-python3 \
    python3-pip \
    libpq5 && \
    apt-get remove --purge --auto-remove -y && \
    rm -rf /var/lib/apt/lists/*

RUN addgroup --gid 1001 --system greenbone && \
    adduser --no-create-home --shell /bin/false --disabled-password --uid 1001 --system --group greenbone

COPY --from=builder /source/dist/* /greenbone-scap/
COPY docker/entrypoint.sh /usr/local/bin/entrypoint

RUN python3 -m pip install --break-system-packages /greenbone-scap/*

RUN mkdir -p /etc/bash_completion.d && \
    greenbone-cve-download --print-completion bash > /etc/bash_completion.d/greenbone-cve-download-complete.bash && \
    echo "source /etc/bash_completion.d/greenbone-cve-download-complete.bash" >> /etc/bash.bashrc && \
    greenbone-cpe-download --print-completion bash > /etc/bash_completion.d/greenbone-cpe-download-complete.bash && \
    echo "source /etc/bash_completion.d/greenbone-cpe-download-complete.bash" >> /etc/bash.bashrc && \
    greenbone-cpe-find --print-completion bash > /etc/bash_completion.d/greenbone-cpe-find-complete.bash && \
    echo "source /etc/bash_completion.d/greenbone-cpe-find-complete.bash" >> /etc/bash.bashrc

RUN chown -R greenbone:greenbone /greenbone-scap && \
    chmod 755 /usr/local/bin/entrypoint

ENTRYPOINT [ "/usr/local/bin/entrypoint" ]

CMD ["/bin/bash"]
