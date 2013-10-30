#!/bin/bash
#
# Create iptables (v4 and v6) rules. Unless [-f] is given, a
# confirmation is asked after loading the new rulesets; if the user
# answers No or doesn't answer, the old ruleset is restored. If the user
# answer Yes (or if the flag [-f] is given), the new ruleset is made
# persistent using iptables-persistent.
#
# This firewall is only targeted towards end-servers, not gateways. In
# particular, there is no NAT'ing at the moment.
#
# Dependencies: netmask(1)
#
# Copyright 2013 Guilhem Moulin <guilhem@fripost.org>
#
# Licensed under the GNU GPL version 3 or higher.
#

set -ue
PATH=/usr/sbin:/usr/bin:/sbin:/bin

timeout=10
force=0

[ "${1:-}" = -f ] && force=1
if ! /usr/bin/tty -s && [ $force -eq 0 ]; then
    echo "Error: Not a TTY. Try with -f (at your own risks)!" >&2
    exit 1
fi

getInteface() {
    /sbin/ip -f "$1" route | sed -nr 's/^default via .*dev (\S+).*/\1/p' | head -1
}

WAN=$( getInteface inet )
WAN6=$(getInteface inet6)

oldv4table=$(mktemp)
newv4table=$(mktemp)

oldv6table=$(mktemp)
newv6table=$(mktemp)

iptables() {
    [ -z "$WAN" ] || { echo "$@" >> "$newv4table"; }
}
ip6tables() {
    [ -z "$WAN6" ] || { echo "$@" >> "$newv6table"; }
}
tgrep() {
    [ -z "$WAN" ]  || { /bin/grep -E -- "$@" "$oldv4table" >> "$newv4table" || true; }
    [ -z "$WAN6" ] || { /bin/grep -E -- "$@" "$oldv6table" >> "$newv6table" || true; }
}
log() {
    /usr/bin/logger -st firewall -p syslog.info -- "$@"
}
fatal() {
    /usr/bin/logger -st firewall -p syslog.err  -- "$@"
    exit 1
}

[ -n "$WAN" -o -n "$WAN6" ] || fatal "Error: couldn't find a network interface"

# Store the existing table
/sbin/iptables-save  -t filter > "$oldv4table"
/sbin/ip6tables-save -t filter > "$oldv6table"

# The usual chains in filter, along with the desired default policies.
cat > "$newv4table" <<- EOF
	*filter
	:INPUT   DROP [0:0]
	:FORWARD DROP [0:0]
	:OUTPUT  DROP [0:0]
EOF
cp -f "$newv4table" "$newv6table"

# Also, keep fail2ban chains
tgrep ':fail2ban-'


# (Host-to-host) IPSec tunnels come first. TODO: test IPSec on IPv6.
tgrep ' -m policy --dir (in|out) --pol ipsec .* --proto esp -j ACCEPT$'


# Allow any IPsec ESP protocol packets to be sent and received.
iptables -A INPUT  -i $WAN -p esp -j ACCEPT
iptables -A OUTPUT -o $WAN -p esp -j ACCEPT

ip6tables -A INPUT  -i $WAN6 -p esp -j ACCEPT
ip6tables -A OUTPUT -o $WAN6 -p esp -j ACCEPT


# Then we have the fail2ban traps
tgrep ' -j fail2ban-\S+$'


##################################################################################
# DROP all RFC1918 addresses, martian networks, multicasts, ...
# Credits to http://newartisans.com/2007/09/neat-tricks-with-iptables/
#            http://baldric.net/loose-iptables-firewall-for-servers/

if [ -n "$WAN" ]; then
    # Private-use networks (RFC 1918) and link local (RFC 3927)
    MyNetwork=$( /bin/ip addr show "$WAN" \
               | sed -nr "s/^\s+inet\s(\S+).*\bscope global ($WAN)?$/\1/p")
    [ -n "$MyNetwork" ] && \
    for ip in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
        [ "$ip" = "$(/usr/bin/netmask -nc $ip $MyNetwork | sed 's/ //g')" ] \
        || iptables -A INPUT  -i $WAN -s "$ip" -j DROP
    done

    # Other martian packets: "This" network, multicast, broadcast (RFCs
    # 1122, 3171 and 919).
    for ip in 0.0.0.0/8 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32; do
        iptables -A INPUT  -i $WAN -s "$ip" -j DROP
        iptables -A INPUT  -i $WAN -d "$ip" -j DROP
    done
fi

# Martian IPv6 packets: ULA (RFC 4193) and site local addresses (RFC
# 3879).
for ip6 in fc00::/7 fec0::/10
do
    ip6tables -A INPUT  -i $WAN6 -s "$ip6" -j DROP
    ip6tables -A INPUT  -i $WAN6 -d "$ip6" -j DROP
done


# DROP INVALID packets immediately.
for chain in INPUT OUTPUT; do
    iptables  -A $chain -m state --state INVALID -j DROP
    ip6tables -A $chain -m state --state INVALID -j DROP
done


# DROP bogus TCP packets.
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP

ip6tables -A INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
ip6tables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP


# Allow all input/output to/from the loopback interface.
iptables -A INPUT  -i lo -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
iptables -A OUTPUT -o lo -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT

ip6tables -A INPUT  -i lo -s ::1 -d ::1 -j ACCEPT
ip6tables -A OUTPUT -o lo -s ::1 -d ::1 -j ACCEPT


# Allow only ICMP of type 0, 3 and 8. The rate-limiting is done directly
# by the kernel (net.ipv4.icmp_ratelimit and net.ipv4.icmp_ratemask
# runtime options). See icmp(7).
for type in  echo-reply destination-unreachable echo-request; do
    iptables -A INPUT  -i $WAN -p icmp -m icmp --icmp-type $type -j ACCEPT
    iptables -A OUTPUT -o $WAN -p icmp -m icmp --icmp-type $type -j ACCEPT
done
ip6tables -A INPUT -i $WAN6 -p icmpv6 -j ACCEPT


##################################################################################
# ACCEPT new connections to the services we provide, or to those we want
# to connect to.

sed -re 's/#.*//; /^\s*$/d' -e 's/^(in|out|inout)\b(.*)/\14\2\n\16\2/' \
        /etc/iptables/services | \
while read dir proto dport sport; do
    # We add two entries per config line: we need to accept the new
    # connection, and latter the reply.
    stNew=NEW,ESTABLISHED
    stEst=ESTABLISHED

    # In-Out means full-duplex
    [[ "$dir" =~ inout ]] && stEst="$stNew"

    optsNew=
    optsEst=
    case "$dport" in
        *,*|*:*) optsNew="--match multiport --dports $dport"
                 optsEst="--match multiport --sports $dport";;
        ?*)      optsNew="--dport $dport"
                 optsEst="--sport $dport";;
    esac
    case "$sport" in
        *,*|*:*) optsNew+=" --match multiport --sports $sport"
                 optsEst+=" --match multiport --dports $sport";;
        ?*)      optsNew+=" --sport $sport"
                 optsEst+=" --dport $sport";;
    esac

    case "$dir" in
        in[46]|inout[46]) iptNew="-A INPUT  -i";  iptEst="-A OUTPUT -o";;
        out[46])          iptNew="-A OUTPUT -o";  iptEst="-A INPUT  -i";;
        *) fatal "Error: Unknown direction: '$dir'."
    esac
    case "$dir" in
        *4) ipt="iptables";  if=$WAN;;
        *6) ipt="ip6tables"; if=$WAN6;;
    esac

    $ipt $iptNew $if -p $proto $optsNew -m state --state $stNew -j ACCEPT
    $ipt $iptEst $if -p $proto $optsEst -m state --state $stEst -j ACCEPT
done


##################################################################################
# And last come the fail2ban rules.
tgrep '^-[AI] fail2ban-\S+ '

echo COMMIT >> "$newv4table"
echo COMMIT >> "$newv6table"

/usr/bin/uniq "$newv4table" | /sbin/iptables-restore
/usr/bin/uniq "$newv6table" | /sbin/ip6tables-restore

save() {
    mkdir -p /etc/iptables
    /sbin/iptables-save  > /etc/iptables/rules.v4
    /sbin/ip6tables-save > /etc/iptables/rules.v6
}

rv=0
if [ $force -eq 1 ]; then
    # At the user's own risks...
    save
else
    echo "Try now to establish NEW connections to the machine."

    read -n1 -t$timeout \
         -p "Are you sure you want to use the new ruleset? (y/N) " \
         ret 2>&1 || { [ $? -gt 128 ] && echo -n "Timeout..."; }
    case "${ret:-N}" in
        [yY]*) echo; save
        ;;
        *) log "Reverting to old ruleset... "; echo
           /sbin/iptables-restore  -c < "$oldv4table"
           /sbin/ip6tables-restore -c < "$oldv6table"
           rv=1
        ;;
    esac
fi

rm -f "$oldv4table" "$newv4table" "$oldv6table" "$newv6table"
exit $rv
