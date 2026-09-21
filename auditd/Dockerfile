FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends auditd audispd-plugins sudo curl gcc vim-tiny openssh-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY audit.rules /etc/audit/rules.d/audit.rules

RUN useradd -m -s /bin/bash labuser && \
    echo 'labuser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

ENTRYPOINT ["/bin/bash", "-c", "auditd && augenrules --load; auditctl -l >/dev/null; tail -f /var/log/audit/audit.log"]
