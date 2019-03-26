FROM alpine:latest
RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories
RUN apk add --no-cache -f \
    xl2tpd \
    tcpdump \
    iputils \
    ppp-radius \
    pptpd \
    rsyslog \
    freeradius-client \
    freeradius-radclient \
    bird \
    iproute2;

# TCPDUMP HACK around https://github.com/dotcloud/docker/issues/5490
RUN mv /usr/sbin/tcpdump /usr/bin/tcpdump

# can be radius or local
ENV IP_ASSIGN_METHOD="local"
ARG IP_ASSIGN_METHOD=${IP_ASSIGN_METHOD}

# lns local ip
ENV LNS_LOCAL_IP="10.0.100.1"
ARG LNS_LOCAL_IP=${LNS_LOCAL_IP}

# lns ip range, valid only if IP_ASSIGN_METHOD=local
ENV LNS_IP_RANGE="10.0.100.101-10.0.100.250"
ARG LNS_IP_RANGE=${LNS_IP_RANGE}

ENV LNS_USER="testuser"
ARG LNS_USER=${LNS_USER}

ENV ENABLE_DYNAMIC_ROUTING="no"
ARG ENABLE_DYNAMIC_ROUTING=${ENABLE_DYNAMIC_ROUTING}

ENV TEST_USER_PASSWORD="123456"
ARG TEST_USER_PASSWORD=${TEST_USER_PASSWORD}

COPY /* /config/* /opt/lns-build/
COPY config/bird/bird.conf /etc/bird.conf
WORKDIR /opt/lns-build
RUN chmod +x entrypoint.sh

EXPOSE 1701/udp
ENTRYPOINT ["./entrypoint.sh"]
CMD ["/usr/sbin/xl2tpd", "-D", "-c", "/etc/xl2tpd/xl2tpd.conf"]
