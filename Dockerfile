# syntax=docker/dockerfile:1

FROM ubuntu:22.04
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && \
    apt-get -y install sudo gcc cmake gdb openssh-server git libpcap-dev build-essential && \
    apt-get -y install libpcap-dev libev-dev libnl-3-dev libnl-genl-3-dev libnl-route-3-dev && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -rm -d /home/ubuntu -s /bin/bash -g root -G sudo -u 1000 dev && \
    service ssh start
COPY . /home/justin/Documents/opennan
WORKDIR /home/justin/Documents/opennan
EXPOSE 22
CMD ["/usr/sbin/sshd","-D"]
# CMD ["bash"]

# docker build -t opennan .
# docker run opennan -p 22:22