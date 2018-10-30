FROM ubuntu:18.04

ENV  JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64
RUN  apt update && DEBIAN_FRONTEND=noninteractive apt upgrade -y
RUN  DEBIAN_FRONTEND=noninteractive apt install -y --fix-missing \
        curl \
        openjdk-8-jre-headless \
        python-pip \
        python3-pip \
        unzip

# Binary Ninja
COPY binaryninja/BinaryNinja.zip /tmp/BinaryNinja.zip
COPY binaryninja/update_to_latest.py /tmp/update_to_latest.py
COPY binaryninja/version_switcher.py /tmp/version_switcher.py
RUN  unzip /tmp/BinaryNinja.zip -d /opt/ && rm /tmp/BinaryNinja.zip && \
     mkdir -p /root/.local/lib/python2.7/site-packages/ && \
     echo "/opt/binaryninja/python" > /root/.local/lib/python2.7/site-packages/binaryninja.pth && \
     mkdir -p /root/.binaryninja/
COPY binaryninja/license.txt /root/.binaryninja/license.dat
RUN  pip install pexpect && python /tmp/update_to_latest.py && rm /tmp/version_switcher.py && rm /tmp/update_to_latest.py

# Grakn
COPY requirements.txt /tmp/requirements.txt
RUN  BROWSER_DOWNLOAD_URL=$(curl --silent https://api.github.com/repos/graknlabs/grakn/releases/latest | python -c "import sys; from json import loads as l; x = l(sys.stdin.read()); print(''.join(s['browser_download_url'] for s in x['assets']))"); \
     curl -fL $BROWSER_DOWNLOAD_URL -o /tmp/grakn.zip && \
     unzip /tmp/grakn.zip -d /opt/ && rm /tmp/grakn.zip && \
     ln -s /opt/grakn*/grakn /usr/local/bin/ && ln -s /opt/grakn*/graql /usr/local/bin/ && \
     pip3 install -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Useful stuff
RUN  DEBIAN_FRONTEND=noninteractive apt install -y --fix-missing \
        tmux \
        vim
#ENTRYPOINT ["/bin/bash"]

ENTRYPOINT ["sh", "-c",  "grakn server start && cd /opt/papermachete && python2.7 paper_machete.py"]
