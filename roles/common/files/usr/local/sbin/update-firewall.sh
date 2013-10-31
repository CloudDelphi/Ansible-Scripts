#!/bin/bash
#
# Create iptables (v4 and v6) rules. Unless one of [-f] or [-c] is
# given, a confirmation is asked after loading the new rulesets; if the
# user answers No or doesn't answer, the old ruleset is restored. If the
# user answer Yes (or if the flag [-f] is given), the new ruleset is
# then stored under /etc/iptables/rules.v[46].
#
# The [-c] flag switch to dry-run (check) mode. The rulesets are not
# applied, but merely checked against the existing ones. If they differ
# the return value is one, and 0 otherwise.
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
check=0

usage() {
    echo "Usage: $0 [-c|-f]" >&2
    exit 1
}

log() {
    /usr/bin/logger -st firewall -p syslog.info -- "$@"
}
fatal() {
    /usr/bin/logger -st firewall -p syslog.err  -- "$@"
    exit 1
}

getInterface() {
    # Get the default interface associated with an address family
    /bin/ip -f "$1" route show to default scope "${2:-global}" \
    | sed -nr '/^default via \S+ dev (\S+).*/ {s//\1/p;q}'
}

iptables() {
    # Fake iptables(8); use the more efficient iptables-restore(8) instead
    [ -z "$WAN" ] || { echo "$@" >> "$newv4"; }
}
ip6tables() {
    # Fake ip6tables(8); use the more efficient ip6tables-restore(8) instead
    [ -z "$WAN6" ] || { echo "$@" >> "$newv6"; }
}
tgrep() {
    # Grep some rules from the old rulesets and add them to each new ruleset.
    [ -z "$WAN" ]  || { grep -E -- "$@" "$oldv4" >> "$newv4" || true; }
    [ -z "$WAN6" ] || { grep -E -- "$@" "$oldv6" >> "$newv6" || true; }
}

ipt-trim() {
    # Remove dynamic chain/rules from the input stream, as they are
    # automatically included by third-party servers (such as strongSwan
    # or fail2ban). The output is ready to be made persistent.
    grep -Ev -e '^:fail2ban-\S' \
             -e "$IPSec_re" \
             -e '-j fail2ban-\S+$' \
             -e "$fail2ban_re"
}

ipt-reset-counters() {
    # Reset the counters. They are not useful for comparing and/or
    # storing persistent ruleset.
    sed -ri -e '/^:/ s/\[[0-9]+:[0-9]+\]$/[0:0]/' \
            -e 's/^\[[0-9]+:[0-9]+\]\s+//' \
            "$@"
}
ipt-save() {
    # Make the current ruleset persistent. (Requires a pre-up hook
    # script to load the rules before the network is configured.)

    [ -d /etc/iptables ] || mkdir /etc/iptables
    /sbin/iptables-save  -t filter | ipt-trim > /etc/iptables/rules.v4
    /sbin/ip6tables-save -t filter | ipt-trim > /etc/iptables/rules.v6

    chmod 0600 /etc/iptables/rules.v4 /etc/iptables/rules.v6
    ipt-reset-counters /etc/iptables/rules.v4 /etc/iptables/rules.v6
}

ipt-diff() {
    /usr/bin/diff -qI '^#' "$1" "$2" >/dev/null
}
isOK() {
    # Check the difference between the persistent, current, and new
    # rulesets (but only if the interface is defined). The current
    # ruleset is trimmed before checking whether it's persistent.
    local v="$1" old="$2" new="$3" if="${4:-}"
    local rv1=0 rv2=0 persistent=/etc/iptables/rules.$v

    ipt-reset-counters "$old"
    [ -z "$if" ] || ipt-diff "$old" "$new" || rv1=$?

    if ! [ -f "$persistent" -a -x /etc/network/if-pre-up.d/iptables ]; then
        rv2=1
    elif [ -n "$if" ]; then
        # Ignore persistency check if the address family is not of
        # globally scoped.
        ipt-trim < "$old" | ipt-diff - "$persistent" || rv2=$?
    fi

    local update="Please run '${0##*/}'."
    [ $rv1 -eq 0 ] || log "WARN: The IP$v firewall is not up to date! $update"
    [ $rv2 -eq 0 ] || log "WARN: The current IP$v firewall is not persistent! $update"

    return $(( $rv1 | $rv2 ))
}


[ $# -le 1 ] || usage
case "${1:-}" in
    -f) force=1;;
    -c) check=1;;
    ?*) usage
esac

[ "${1:-}" = -f ] && force=1
if ! /usr/bin/tty -s && [ $force -eq 0 ]; then
    echo "Error: Not a TTY. Try with -f (at your own risks)!" >&2
    exit 1
fi

WAN=$( getInterface inet )
WAN6=$(getInterface inet6)

oldv4=$(mktemp)
newv4=$(mktemp)

oldv6=$(mktemp)
newv6=$(mktemp)

[ -n "$WAN" -o -n "$WAN6" ] || fatal "Error: couldn't find a network interface"

IPSec_re=' -m policy --dir (in|out) --pol ipsec .* --proto esp -j ACCEPT$'
fail2ban_re='^(\[[0-9]+:[0-9]+\]\s+)?-A fail2ban-\S'

# Store the existing table
/sbin/iptables-save  -ct filter > "$oldv4"
/sbin/ip6tables-save -ct filter > "$oldv6"

# The usual chains in filter, along with the desired default policies.
cat > "$newv4" <<- EOF
	*filter
	:INPUT   DROP [0:0]
	:FORWARD DROP [0:0]
	:OUTPUT  DROP [0:0]
	:fail2ban -   [0:0]
EOF
cp -f "$newv4" "$newv6"

# Keep fail2ban chains, traps, and existing rules.
tgrep ':fail2ban-\S'
tgrep ' -j fail2ban-\S+$'
tgrep "$fail2ban_re"


# (Host-to-host) IPSec tunnels come first. TODO: test IPSec on IPv6.
tgrep "$IPSec_re"


# Allow any IPsec ESP protocol packets to be sent and received.
iptables -A INPUT  -i $WAN -p esp -j ACCEPT
iptables -A OUTPUT -o $WAN -p esp -j ACCEPT

ip6tables -A INPUT  -i $WAN6 -p esp -j ACCEPT
ip6tables -A OUTPUT -o $WAN6 -p esp -j ACCEPT


##################################################################################
# DROP all RFC1918 addresses, martian networks, multicasts, ...
# Credits to http://newartisans.com/2007/09/neat-tricks-with-iptables/
#            http://baldric.net/loose-iptables-firewall-for-servers/

if [ -n "$WAN" ]; then
    # Private-use networks (RFC 1918) and link local (RFC 3927)
    MyNetwork=$( /bin/ip -4 addr show dev "$WAN" scope global \
               | sed -nr 's/^\s+inet\s(\S+).*/\1/p')
    [ -n "$MyNetwork" ] && \
    for ip in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
        # Don't lock us out if we are behind a NAT ;-)
        [ "$ip" = "$(/usr/bin/netmask -nc $ip $MyNetwork | sed 's/ //g')" ] \
        || iptables -A INPUT -i $WAN -s "$ip" -j DROP
    done

    # Other martian packets: "This" network, multicast, broadcast (RFCs
    # 1122, 3171 and 919).
    for ip in 0.0.0.0/8 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32; do
        iptables -A INPUT -i $WAN -s "$ip" -j DROP
        iptables -A INPUT -i $WAN -d "$ip" -j DROP
    done
fi

# Martian IPv6 packets: ULA (RFC 4193) and site local addresses (RFC
# 3879).
for ip6 in fc00::/7 fec0::/10
do
    ip6tables -A INPUT -i $WAN6 -s "$ip6" -j DROP
    ip6tables -A INPUT -i $WAN6 -d "$ip6" -j DROP
done


# DROP INVALID packets immediately.
for chain in INPUT OUTPUT; do
    iptables  -A $chain -m state --state INVALID -j DROP
    ip6tables -A $chain -m state --state INVALID -j DROP
done


# DROP bogus TCP packets.
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP

ip6tables -A INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
ip6tables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP

# Prepare fail2ban. We make fail2ban insert its rules in a dedicated
# chain, so that it doesn't mess up the existing rules.
# XXX: As of Wheezy, fail2ban is IPv4 only. See
#      https://github.com/fail2ban/fail2ban/issues/39 for the current
#      state of the art.
iptables -A INPUT -i $WAN -j fail2ban


# Allow all input/output to/from the loopback interface.
iptables -A INPUT  -i lo -s 127.0.0.1/32 -d 127.0.0.1/32 -j ACCEPT
iptables -A OUTPUT -o lo -s 127.0.0.1/32 -d 127.0.0.1/32 -j ACCEPT

ip6tables -A INPUT  -i lo -s ::1/128 -d ::1/128 lo -j ACCEPT
ip6tables -A OUTPUT -o lo -s ::1/128 -d ::1/128 lo -j ACCEPT


# Allow only ICMP of type 0, 3 and 8. The rate-limiting is done directly
# by the kernel (net.ipv4.icmp_ratelimit and net.ipv4.icmp_ratemask
# runtime options). See icmp(7).
for type in  'echo-reply' 'destination-unreachable' 'echo-request'; do
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
    [[ "$dir" =~ ^inout ]] && stEst="$stNew"

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

echo COMMIT >> "$newv4"
echo COMMIT >> "$newv6"

netns=
innetns=
if [ $check -eq 1 ]; then
    # Create an alternative net namespace in which we apply the ruleset,
    # so we can easily get a normalized version we can compare latter.
    # See http://bugzilla.netfilter.org/show_bug.cgi?id=790
    netns="ipt-firewall-test-$$"
    /bin/ip netns add $netns
    innetns="/bin/ip netns exec $netns"
fi

/usr/bin/uniq "$newv4" | $innetns /sbin/iptables-restore
/usr/bin/uniq "$newv6" | $innetns /sbin/ip6tables-restore

rv=0
if [ $check -eq 1 ]; then
    # Normalize the new rulesets
    $innetns /sbin/iptables-save  -t filter > "$newv4"
    $innetns /sbin/ip6tables-save -t filter > "$newv6"
    /bin/ip netns del $netns

    isOK v4 "$oldv4" "$newv4" $WAN  || rv=$(( $rv | $? ))
    isOK v6 "$oldv6" "$newv6" $WAN6 || rv=$(( $rv | $? ))

elif [ $force -eq 1 ]; then
    # At the user's own risks...
    ipt-save
else
    echo "Try now to establish NEW connections to the machine."

    read -n1 -t$timeout \
         -p "Are you sure you want to use the new ruleset? (y/N) " \
         ret 2>&1 || { [ $? -gt 128 ] && echo -n "Timeout..."; }
    case "${ret:-N}" in
        [yY]*) echo; ipt-save
        ;;
        *) echo; log "Reverting to old ruleset... "
           /sbin/iptables-restore  -c < "$oldv4"
           /sbin/ip6tables-restore -c < "$oldv6"
           rv=1
        ;;
    esac
fi

rm -f "$oldv4" "$newv4" "$oldv6" "$newv6"
exit $rv
