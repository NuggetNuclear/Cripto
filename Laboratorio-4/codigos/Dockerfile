FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
       --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash gabrielDOCKER \
    && echo 'gabrielDOCKER:UdpLab4Cripto2026!' | chpasswd

RUN rm -f /etc/ssh/ssh_host_* \
    && ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

RUN mkdir -p /run/sshd && chmod 0755 /run/sshd

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
