FROM ubuntu:18.04

# Prerequisites
ENV  JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64
RUN  apt update && DEBIAN_FRONTEND=noninteractive apt upgrade -y
RUN  DEBIAN_FRONTEND=noninteractive apt install -y --fix-missing \
        curl \
        libgl1-mesa-glx \
        openjdk-8-jre-headless \
        python-pip \
        python3-pip \
        unzip \
        xvfb

# Binary Ninja
COPY binaryninja/BinaryNinja.zip /tmp/BinaryNinja.zip
COPY binaryninja/docker_install.py /tmp/docker_install.py
RUN  unzip -q /tmp/BinaryNinja.zip -d /opt/ && rm /tmp/BinaryNinja.zip && \
     ln -s /opt/binaryninja/binaryninja /usr/local/bin/ && \
     mkdir -p /root/.local/lib/python2.7/site-packages/ && \
     echo "/opt/binaryninja/python" > /root/.local/lib/python2.7/site-packages/binaryninja.pth && \
     mkdir -p /root/.local/lib/python3.6/site-packages/ && \
     echo "/opt/binaryninja/python" > /root/.local/lib/python3.6/site-packages/binaryninja.pth && \
     mkdir -p /root/.binaryninja/plugins/pm_analysis/
COPY pm_analysis.py /root/.binaryninja/plugins/pm_analysis/__init__.py
COPY binaryninja/license.txt /root/.binaryninja/license.dat
RUN  pip install pexpect && python /tmp/docker_install.py --headless && \
     rm /tmp/docker_install.py && pip uninstall -y pexpect
# old versions of Binary Ninja fail to update without launching the GUI
RUN  timeout 10s xvfb-run binaryninja || :
RUN  apt remove -y libgl1-mesa-glx xvfb && apt autoremove -y && apt clean
#COPY binaryninja/settings.json /root/.binaryninja/settings.json

# Grakn
RUN  BROWSER_DOWNLOAD_URL=$(curl --silent https://api.github.com/repos/graknlabs/grakn/releases/latest | python -c "import sys; from json import loads as l; x = l(sys.stdin.read()); print(''.join(s['browser_download_url'] for s in x['assets']))"); \
     curl -fL $BROWSER_DOWNLOAD_URL -o /tmp/grakn.zip && \
     unzip -q /tmp/grakn.zip -d /opt/ && rm /tmp/grakn.zip && \
     ln -s /opt/grakn*/grakn /usr/local/bin/ && ln -s /opt/grakn*/graql /usr/local/bin/ && \
     pip3 install grakn

# Useful stuff
RUN  DEBIAN_FRONTEND=noninteractive apt install -y --fix-missing \
        tmux \
        vim

#ENTRYPOINT ["sh", "-c",  "grakn server start && cd /opt/papermachete && python2.7 paper_machete.py"]

# Useful for debugging
ENTRYPOINT ["/bin/bash"]