#!/usr/bin/env sh

set -e

# Init TCP\IP Vars

## Enable IP Forwarding
sysctl -w net.ipv4.ip_forward=1
## RPF - Loose mode for Internal Interface ONLY, all other interfaces in STRICT mode.
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w net.ipv4.conf.eth0.rp_filter=0
## Enable proxy-arp for internal services to work with clients.
echo 1 > /proc/sys/net/ipv4/conf/all/proxy_arp


# IP Tables
iptables -t filter -A FORWARD 
iptables -t filter -A FORWARD -s 10.0.0.0/8 -i ppp+ -j ACCEPT
iptables -t filter -A FORWARD -d 10.0.0.0/8 -o ppp+ -j ACCEPT

# Mark I\O packets that origin from L2TP tunnel with 0x2 mark.
iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -m mark --mark 0x1 -j ACCEPT
iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j MARK --set-mark 0x1

iptables-save > /etc/iptables/rules.v4


# IP Routing
## Add policy tables for marked packets.
echo "100       to_snort" >> /etc/iproute2/rt_tables;
echo "200       to_bypass" >> /etc/iproute2/rt_tables;

## Fill up  tables.
ip route flush table to_snort

## Add ip rule for marked packets.
ip rule add fwmark 0x1 table to_snort priority 200

## Update configs
cat xl2tpd.conf > /etc/xl2tpd/xl2tpd.conf

sed -i "s|;local ip.*|local ip = $LNS_LOCAL_IP|" /etc/xl2tpd/xl2tpd.conf

if [ "$IP_ASSIGN_METHOD" == "local" ]; then
    sed -i "s|;assign ip.*|assign ip = yes|" /etc/xl2tpd/xl2tpd.conf
    sed -i "s|;ip range.*|ip range = $LNS_IP_RANGE|" /etc/xl2tpd/xl2tpd.conf
    sed -i "s|plugin|#plugin|g" options.xl2tpd

    # generate new testuser password to xl2tpd auth
    TEST_USER_PASSWORD=${RANDOM}${RANDOM}
    echo "testuser * $TEST_USER_PASSWORD *" >> /etc/ppp/chap-secrets
elif [ "$IP_ASSIGN_METHOD" != "radius" ]; then
    echo "bad IP Allocation method"
    exit 1
fi

cat options.xl2tpd > /etc/ppp/options.xl2tpd
cat pptpd.conf > /etc/pptpd.conf

# freeRADIUS Client
## Update freeRADIUS Client servers.
echo "$FREERADIUS_HOST $FREERADIUS_SECRET" >> /etc/radiusclient/servers

## Update configs
cat dictionary.microsoft > /etc/radiusclient/dictionary.microsoft
cat dictionary.merit > /etc/radiusclient/dictionary.merit

sed -i -e "/dictionary.merit/d" -e "/dictionary.microsoft/d" -e "/-Traffic/d" /etc/radiusclient/dictionary

## Update configs
cat dictionary > /etc/radiusclient/dictionary
sed -i "s/ATTRIBUTE\tNAS-IPv6-Address\t95\tstring/#ATTRIBUTE\tNAS-IPv6-Address\t95\tstring/g"  /etc/radiusclient/dictionary
sed -i "s/ATTRIBUTE\tFramed-Interface-Id\t96\tstring/#ATTRIBUTE\tFramed-Interface-Id\t96\tstring/g"  /etc/radiusclient/dictionary
sed -i "s/ATTRIBUTE\tFramed-IPv6-Prefix\t97\tipv6prefix/#ATTRIBUTE\tFramed-IPv6-Prefix\t97\tipv6prefix/g"  /etc/radiusclient/dictionary
sed -i "s/ATTRIBUTE\tLogin-IPv6-Host\t98\tstring/#ATTRIBUTE\tLogin-IPv6-Host\t98\tstring/g"  /etc/radiusclient/dictionary
sed -i "s/ATTRIBUTE\tFramed-IPv6-Route\t99\tstring/#ATTRIBUTE\tFramed-IPv6-Route\t99\tstring/g"  /etc/radiusclient/dictionary
sed -i "s/ATTRIBUTE\tFramed-IPv6-Pool\t100\tstring/#ATTRIBUTE\tFramed-IPv6-Pool\t100\tstring/g"  /etc/radiusclient/dictionary
sed -i "s/ATTRIBUTE\tError-Cause\t101\tinteger/#ATTRIBUTE\tError-Cause\t101\tinteger/g"  /etc/radiusclient/dictionary
sed -i "s/ATTRIBUTE\tEAP-Key-Name\t102\tstring/#ATTRIBUTE\tEAP-Key-Name\t102\tstring/g"  /etc/radiusclient/dictionary
sed -i "s/ATTRIBUTE\tFramed-IPv6-Address\t168\tipv6addr/#ATTRIBUTE\tFramed-IPv6-Address\t168\tipv6addr/g"  /etc/radiusclient/dictionary
sed -i "s/ATTRIBUTE\tDNS-Server-IPv6-Address\t169\tipv6addr/#ATTRIBUTE\tDNS-Server-IPv6-Address\t169\tipv6addr/g"  /etc/radiusclient/dictionary
sed -i "s/ATTRIBUTE\tRoute-IPv6-Information\t170\tipv6prefix/#ATTRIBUTE\tRoute-IPv6-Information\t170\tipv6prefix/g"  /etc/radiusclient/dictionary

## Update configs
cat radiusclient.conf > /etc/radiusclient/radiusclient.conf
sed -i -e "s|FREERADIUS_HOST|$FREERADIUS_HOST|g" /etc/radiusclient/radiusclient.conf

# Start syslog
/usr/sbin/rsyslogd

# Start Bird
bird

if [ -n "$TEST_USER_PASSWORD" ]; then
   echo "###################################"
   echo "## testuser password is $TEST_USER_PASSWORD ##"
   echo "###################################"
fi

# Run xl2tpd service.
exec "$@"
