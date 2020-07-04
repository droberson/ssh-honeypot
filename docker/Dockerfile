FROM alpine:3.12 AS build

RUN apk add --update alpine-sdk clang git libssh-dev openssl openssh json-c-dev libssh2-dev \
    && git clone --depth=1 --single-branch -j "$(nproc)" https://github.com/droberson/ssh-honeypot.git /git-ssh-honeypot \
    && cd /git-ssh-honeypot \
    && make -j "$(nproc)" \
    && chmod 0777 ./bin/ssh-honeypot

# ====== APP ======
FROM nlss/base-alpine:3.12

COPY --from=build /git-ssh-honeypot/bin/ssh-honeypot /bin/ssh-honeypot

RUN apk add --update --no-cache libssh-dev json-c-dev openssh \
    && adduser --shell /bin/false --disabled-password --gecos "Honeycomb" --home "/home/honeycomb" "honeycomb" \
    && mkdir -p /home/honeycomb/{log,rsa}

COPY ["./rootfs", "/"]

VOLUME ["/home/honeycomb/log", "/home/honeycomb/rsa"]

EXPOSE 2022/TCP
