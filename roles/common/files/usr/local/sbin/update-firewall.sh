#!/bin/bash

# Create iptables (v4 and v6) rules.  Unless one of [-f] or [-c] is
# given, or if the ruleset is unchanged, a confirmation is asked after
# loading the new rulesets; if the user answers No or doesn't answer,
# the old ruleset is restored.  If the user answer Yes (or if the flag
# [-f] is given), the new ruleset is made persistent (requires a pre-up
# hook) by moving it to /etc/iptables/rules.v[46].
#
# The [-c] flag switch to dry-run (check) mode.  The rulesets are not
# applied, but merely checked against the existing ones.  The return
# value is 0 iff. they do not differ.
#
# This firewall is only targeted towards end-servers, not gateways.  In
# particular, there is no NAT'ing at the moment.
#
# Dependencies: netmask(1)
#
# Copyright © 2013 Guilhem Moulin <guilhem@fripost.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

set -ue
PATH=/usr/sbin:/usr/bin:/sbin:/bin
timeout=10

force=0
check=0
verbose=0
addrfam=

secproto=esp # must match /etc/ipsec.conf; ESP is the default (vs AH/IPComp)
if [ -x /usr/sbin/ipsec ] && /usr/sbin/ipsec status >/dev/null; then
    ipsec=y
else
    ipsec=n
fi

fail2ban_re='^(\[[0-9]+:[0-9]+\]\s+)?-A fail2ban-\S'
IPSec_re=" -m policy --dir (in|out) --pol ipsec --reqid [0-9]+ --proto $secproto -j ACCEPT$"
declare -A rss=() tables=()

usage() {
    cat >&2 <<- EOF
		Usage: $0 [OPTIONS]

		Options:
		    -f force:   no confirmation asked
		    -c check:   check (dry-run) mode
		    -v verbose: see the difference between old and new ruleset
		    -4 IPv4 only
		    -6 IPv6 only
	EOF
    exit 1
}

log() {
    /usr/bin/logger -st firewall -p user.info -- "$@"
}
fatal() {
    /usr/bin/logger -st firewall -p user.err  -- "$@"
    exit 1
}

iptables() {
    # Fake iptables/ip6tables(8); use the more efficient
    # iptables-restore(8) instead.
    echo "$@" >> "$new";
}
commit() {
    # End a table
    echo COMMIT >> "$new"
}
inet46() {
    case "$1" in
        4) echo "$2";;
        6) echo "$3";;
    esac
}
ipt-chains() {
    # Define new (tables and) chains.
    while [ $# -gt 0 ]; do
        case "$1" in
            ?*:*) echo ":${1%:*} ${1##*:} [0:0]";;
            ?*)   echo "*$1";;
        esac
        shift
    done >> "$new"
}

ipt-trim() {
    # Remove dynamic chain/rules from the input stream, as they are
    # automatically included by third-party servers (such as strongSwan
    # or fail2ban).  The output is ready to be made persistent.
    grep -Ev -e '^:fail2ban-\S' \
             -e "$IPSec_re" \
             -e '-j fail2ban-\S+$' \
             -e "$fail2ban_re"
}

ipt-diff() {
    # Get the difference between two rulesets.
    if [ $verbose -eq 1 ]; then
        /usr/bin/diff -u -I '^#' "$1" "$2"
    else
        /usr/bin/diff -q -I '^#' "$1" "$2" >/dev/null
    fi
}

ipt-persist() {
    # Make the current ruleset persistent.  (Requires a pre-up hook
    # script to load the rules before the network is configured.)

    log "Making ruleset persistent... "
    [ -d /etc/iptables ] || mkdir /etc/iptables

    local f rs table
    for f in "${!tables[@]}"; do
        ipts=/sbin/$(inet46 $f iptables ip6tables)-save
        rs=/etc/iptables/rules.v$f

        for table in ${tables[$f]}; do
            /bin/ip netns exec $netns $ipts -t $table
        done | ipt-trim > "$rs"
        chmod 0600 "$rs"
    done
}

ipt-revert() {
    [ $check -eq 0 ] || return
    log "Reverting to old ruleset... "

    local rs
    for f in "${!rss[@]}"; do
        /sbin/$(inet46 $f iptables ip6tables)-restore -c < "${rss[$f]}"
        rm -f "${rss[$f]}"
    done
    exit 1
}

run() {
    # Build and apply the firewall for IPv4/6.
    local f="$1"
    local ipt=/sbin/$(inet46 $f iptables ip6tables)
    tables[$f]=filter

    # The default interface associated with this address.
    local if=$( /bin/ip -$f -o route show to default scope global \
              | sed -nr '/^default via \S+ dev (\S+).*/ {s//\1/p;q}' )

    # Store the old (current) ruleset
    local old=$(mktemp --tmpdir current-rules.v$f.XXXXXX) \
          new=$(mktemp --tmpdir new-rules.v$f.XXXXXX)
    for table in ${tables[$f]}; do
        $ipt-save -ct $table
    done > "$old"
    rss[$f]="$old"

    local fail2ban=0
    # XXX: As of Wheezy, fail2ban is IPv4 only.  See
    #      https://github.com/fail2ban/fail2ban/issues/39 for the current
    #      state of the art.
    if [ "$f" = 4 ] && which /usr/bin/fail2ban-server >/dev/null; then
        fail2ban=1
    fi

    # The usual chains in filter, along with the desired default policies.
    ipt-chains filter INPUT:DROP FORWARD:DROP OUTPUT:DROP

    if [ ! "$if" ]; then
        # If the interface is not configured, we stop here and DROP all
        # packets by default.  Thanks to the pre-up hook this tight
        # policy will be activated whenever the interface goes up.
        commit
        mv "$new" /etc/iptables/rules.v$f
        return 0
    fi

    # Fail2ban-specific chains and traps
    if [ $fail2ban -eq 1 ]; then
        echo ":fail2ban - [0:0]"
        # Don't remove existing rules & traps in the current rulest
        grep    -- '^:fail2ban-\S'      "$old" || true
        grep -E -- ' -j fail2ban-\S+$'  "$old" || true
        grep -E -- "$fail2ban_re"       "$old" || true
    fi >> "$new"

    if [ "$f" = 4 -a "$ipsec" = y ]; then
        # Our IPSec tunnels are IPv4 only.
        # (Host-to-host) IPSec tunnels come first.
        grep -E -- "$IPSec_re" "$old" >> "$new" || true

        # Allow any IPsec $secproto protocol packets to be sent and received.
        iptables -A INPUT  -i $if -p $secproto -j ACCEPT
        iptables -A OUTPUT -o $if -p $secproto -j ACCEPT
    fi


    ########################################################################
    # DROP all RFC1918 addresses, martian networks, multicasts, ...
    # Credits to http://newartisans.com/2007/09/neat-tricks-with-iptables/
    #            http://baldric.net/loose-iptables-firewall-for-servers/

    local ip
    if [ "$f" = 4 -a "$ipsec" = y ]; then
        # Private-use networks (RFC 1918) and link local (RFC 3927)
        local MyIPSec="$( /bin/ip -4 -o route show table 220 dev $if | sed 's/\s.*//' )"
        local MyNetwork="$( /bin/ip -4 -o address show dev $if scope global \
                          | sed -nr "s/^[0-9]+:\s+$if\s+inet\s(\S+).*/\1/p" \
                          | while read ip; do
                              for ips in $MyIPSec; do
                                [ "$ips" = "$(/usr/bin/netmask -nc "$ip" "$ips" | sed 's/^ *//')" ] || echo "$ip"
                              done
                            done
                          )"
        [ "$MyNetwork" ] && \
        for ip in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
            # Don't lock us out if we are behind a NAT ;-)
            for myip in $MyNetwork; do
                [ "$ip" = "$(/usr/bin/netmask -nc "$ip" "$myip" | sed 's/^ *//')" ] \
                || iptables -A INPUT -i $if -s "$ip" -j DROP
            done
        done

        # Other martian packets: "This" network, multicast, broadcast (RFCs
        # 1122, 3171 and 919).
        for ip in 0.0.0.0/8 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32; do
            iptables -A INPUT -i $if -s "$ip" -j DROP
            iptables -A INPUT -i $if -d "$ip" -j DROP
        done

    elif [ "$f" = 6 ]; then
        # Martian IPv6 packets: ULA (RFC 4193) and site local addresses
        # (RFC 3879).
        for ip in fc00::/7 fec0::/10; do
            iptables -A INPUT -i $if -s "$ip" -j DROP
            iptables -A INPUT -i $if -d "$ip" -j DROP
        done
    fi

    # DROP INVALID packets immediately.
    iptables -A INPUT  -m state --state INVALID -j DROP
    iptables -A OUTPUT -m state --state INVALID -j DROP

    # DROP bogus TCP packets.
    iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
    iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
    iptables -A INPUT -p tcp \! --syn -m state --state NEW      -j DROP

    # Allow all input/output to/from the loopback interface.
    local localhost=$(inet46 $f '127.0.0.1/8' '::1/128')
    iptables -A INPUT  -i lo -s "$localhost" -d "$localhost" -j ACCEPT
    iptables -A OUTPUT -o lo -s "$localhost" -d "$localhost" -j ACCEPT
    if [ "$f" = 4 -a "$ipsec" = y ]; then
        # Allow local access to our virtual IP
        /bin/ip -4 -o route show table 220 dev $if \
        | sed -nr 's/.*\ssrc\s+([[:digit:].]{7,15})(\s.*)?$/\1/p' \
        | while read ips; do
            iptables -A INPUT  -i lo -s "$ips" -d "$ips" -j ACCEPT
            iptables -A OUTPUT -o lo -s "$ips" -d "$ips" -j ACCEPT
        done
    fi

    # Prepare fail2ban.  We make fail2ban insert its rules in a
    # dedicated chain, so that it doesn't mess up the existing rules.
    [ $fail2ban -eq 1 ] && iptables -A INPUT -i $if -j fail2ban

    if [ "$f" = 4 ]; then
        # Allow only ICMP of type 0, 3 and 8.  The rate-limiting is done
        # directly by the kernel (net.ipv4.icmp_ratelimit and
        # net.ipv4.icmp_ratemask runtime options).  See icmp(7).
        local t
        for t in  'echo-reply' 'destination-unreachable' 'echo-request'; do
            iptables -A INPUT  -p icmp -m icmp --icmp-type $t -j ACCEPT
            iptables -A OUTPUT -p icmp -m icmp --icmp-type $t -j ACCEPT
        done
    elif [ $f = 6 ]; then
        iptables -A INPUT  -p icmpv6 -j ACCEPT
        iptables -A OUTPUT -p icmpv6 -j ACCEPT
    fi


    ########################################################################
    # ACCEPT new connections to the services we provide, or to those we want
    # to connect to.

    sed -re 's/#.*//; /^\s*$/d' -e "s/^(in|out|inout)$f?(\s.*)/\1\2/" \
            /etc/iptables/services | \
    grep -Ev '^(in|out|inout)\S\s' | \
    while read dir proto dport sport; do
        # We add two entries per config line: we need to accept the new
        # connection, and latter the reply.
        local stNew=NEW,ESTABLISHED
        local stEst=ESTABLISHED

        # In-Out means full-duplex
        [[ "$dir" =~ ^inout ]] && stEst="$stNew"

        local iptNew= iptEst= optsNew= optsEst=
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
            in|inout) iptNew="-A INPUT  -i";  iptEst="-A OUTPUT -o";;
            out)      iptNew="-A OUTPUT -o";  iptEst="-A INPUT  -i";;
            *) fatal "Error: Unknown direction: '$dir'."
        esac

        iptables $iptNew $if -p $proto $optsNew -m state --state $stNew -j ACCEPT
        iptables $iptEst $if -p $proto $optsEst -m state --state $stEst -j ACCEPT
    done

    ########################################################################
    commit


    local rv1=0 rv2=0 persistent=/etc/iptables/rules.v$f
    local oldz=$(mktemp --tmpdir current-rules.v$f.XXXXXX)

    # Reset the counters.  They are not useful for comparing and/or
    # storing persistent ruleset.  (We don't use sed -i because we want
    # to restore the counters when reverting.)
    sed -r -e '/^:/ s/\[[0-9]+:[0-9]+\]$/[0:0]/' \
           -e 's/^\[[0-9]+:[0-9]+\]\s+//' \
           "$old" > "$oldz"

    /usr/bin/uniq "$new" | /bin/ip netns exec $netns $ipt-restore || ipt-revert

    for table in ${tables[$f]}; do
       /bin/ip netns exec $netns $ipt-save -t $table
    done > "$new"

    ipt-diff "$oldz" "$new" || rv1=$?

    if ! [ -f "$persistent" -a -x /etc/network/if-pre-up.d/iptables ]; then
        rv2=1
    else
        ipt-trim < "$oldz" | ipt-diff - "$persistent" || rv2=$?
    fi

    local update="Please run '${0##*/}'."
    if [ $check -eq 0 ]; then
        /usr/bin/uniq "$new" | $ipt-restore || ipt-revert
    else
        if [ $rv1 -ne 0 ]; then
            log "WARN: The IPv$f firewall is not up to date! $update"
        fi
        if [ $rv2 -ne 0 ]; then
            log "WARN: The current IPv$f firewall is not persistent! $update"
        fi
    fi

    rm -f "$oldz" "$new"
    return $(( $rv1 | $rv2 ))
}


# Parse options
while [ $# -gt 0 ]; do
    case "$1" in
        -?*) for (( k=1; k<${#1}; k++ )); do
                o="${1:$k:1}"
                case "$o" in
                    4|6) addrfam="$o";;
                    c) check=1;;
                    f) force=1;;
                    v) verbose=1;;
                    *) usage;;
                esac
            done
        ;;
        *) usage;;
    esac
    shift
done

# If we are going to apply the ruleset, we should either have a TTY, or
# use -f.
if ! /usr/bin/tty -s && [ $force -eq 0 -a $check -eq 0 ]; then
    echo "Error: Not a TTY. Try with -f (at your own risks!)" >&2
    exit 1
fi

# Create an alternative net namespace in which we apply the ruleset, so
# we can easily get a normalized version we can compare latter.  See
# http://bugzilla.netfilter.org/show_bug.cgi?id=790
netns="ipt-firewall-test-$$"
/bin/ip netns add $netns

trap '/bin/ip netns del $netns 2>/dev/null || true; ipt-revert' SIGINT
trap '/bin/ip netns del $netns; rm -f "${rss[@]}"'              EXIT

rv=0
for f in ${addrfam:=4 6}; do
    run $f || rv=$(( $rv | $? ))
done

if [ $force -eq 1 ]; then
    # At the user's own risks...
    ipt-persist

elif [ $check -eq 1 -o $rv -eq 0 ]; then
    # Nothing to do, we're all set.
    exit $rv

else
    echo "Try now to establish NEW connections to the machine."

    read -n1 -t$timeout \
         -p "Are you sure you want to use the new ruleset? (y/N) " \
         ret 2>&1 || { [ $? -gt 128 ] && echo -n "Timeout..."; }
    case "${ret:-N}" in
        [yY]*) echo; ipt-persist
        ;;
        *) echo; ipt-revert
        ;;
    esac
fi
