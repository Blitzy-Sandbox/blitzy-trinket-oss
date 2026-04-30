# Java 8 (Oracle) Dockerfile
# Base image: Ubuntu
# Installs: Java 8
  
# SECURITY: java shell base image audited per AAP §0.5.2 Strategy F / R6 (Corretto 8 LTS through 2030)
FROM amazoncorretto:8

RUN yum -y install python3 \
    python3-pip \
    shadow-utils \
    curl \
    tar \
    gzip

RUN adduser trinket
USER trinket
WORKDIR /home/trinket
ENV HOME /home/trinket

RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.2/install.sh | bash

ENV NVM_DIR /home/trinket/.nvm
ENV NODE_VERSION 14.21.1

RUN source $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default

ENV NODE_PATH $NVM_DIR/v$NODE_VERSION/lib/node_modules
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH

RUN npm install -g pm2
RUN mkdir -p /tmp/sessions && chmod 777 /tmp/sessions
COPY ./trinket /home/trinket

RUN npm install >/dev/null 2>&1
EXPOSE 8010
CMD ["pm2-runtime", "start", "server.js"]
