#!/bin/sh 
#
#  This is automatically generated file. DO NOT MODIFY !
#
#  Firewall Builder  fwb_ipt v5.3.7
#
#  Generated Sat Jan 18 08:48:04 2025 AEST by acas
#
# files: * opi2.fw /etc/fw/opi2.fw
#
# Compiled for iptables (any version)
#
# This template is intended for a simple server with one interface. "Assume firewall is part of any"
# option is off, IP forwarding is off.




FWBDEBUG=""

PATH="/sbin:/usr/sbin:/bin:/usr/bin:${PATH}"
export PATH



LSMOD="/sbin/lsmod"
MODPROBE="/sbin/modprobe"
IPTABLES="/sbin/iptables"
IP6TABLES="/sbin/ip6tables"
IPTABLES_RESTORE="/sbin/iptables-restore"
IP6TABLES_RESTORE="/sbin/ip6tables-restore"
IP="/sbin/ip"
IFCONFIG="/sbin/ifconfig"
VCONFIG="/sbin/vconfig"
BRCTL="/sbin/brctl"
IFENSLAVE="/sbin/ifenslave"
IPSET="/usr/sbin/ipset"
LOGGER="/usr/bin/logger"

log() {
    echo "$1"
    which "$LOGGER" >/dev/null 2>&1 && $LOGGER -p info "$1"
}

getInterfaceVarName() {
    echo $1 | sed 's/\./_/'
}

getaddr_internal() {
    dev=$1
    name=$2
    af=$3
    L=$($IP $af addr show dev $dev |  sed -n '/inet/{s!.*inet6* !!;s!/.*!!p}' | sed 's/peer.*//')
    test -z "$L" && { 
        eval "$name=''"
        return
    }
    eval "${name}_list=\"$L\"" 
}

getnet_internal() {
    dev=$1
    name=$2
    af=$3
    L=$($IP route list proto kernel | grep $dev | grep -v default |  sed 's! .*$!!')
    test -z "$L" && { 
        eval "$name=''"
        return
    }
    eval "${name}_list=\"$L\"" 
}


getaddr() {
    getaddr_internal $1 $2 "-4"
}

getaddr6() {
    getaddr_internal $1 $2 "-6"
}

getnet() {
    getnet_internal $1 $2 "-4"
}

getnet6() {
    getnet_internal $1 $2 "-6"
}

# function getinterfaces is used to process wildcard interfaces
getinterfaces() {
    NAME=$1
    $IP link show | grep ": $NAME" | while read L; do
        OIFS=$IFS
        IFS=" :"
        set $L
        IFS=$OIFS
        echo $2
    done
}

diff_intf() {
    func=$1
    list1=$2
    list2=$3
    cmd=$4
    for intf in $list1
    do
        echo $list2 | grep -q $intf || {
        # $vlan is absent in list 2
            $func $intf $cmd
        }
    done
}

find_program() {
  PGM=$1
  which $PGM >/dev/null 2>&1 || {
    echo "\"$PGM\" not found"
    exit 1
  }
}
check_tools() {
  find_program which
  find_program $IPTABLES 
  find_program $MODPROBE 
  find_program $IP 
}
reset_iptables_v4() {
  local list

  $IPTABLES  -P OUTPUT  DROP
  $IPTABLES  -P INPUT   DROP
  $IPTABLES  -P FORWARD DROP

  while read table; do
      list=$($IPTABLES  -t $table -L -n)
      printf "%s" "$list" | while read c chain rest; do
      if test "X$c" = "XChain" ; then
        $IPTABLES  -t $table -F $chain
      fi
      done
      $IPTABLES  -t $table -X
  done < /proc/net/ip_tables_names
}

reset_iptables_v6() {
  local list

  $IP6TABLES  -P OUTPUT  DROP
  $IP6TABLES  -P INPUT   DROP
  $IP6TABLES  -P FORWARD DROP

  while read table; do
      list=$($IP6TABLES  -t $table -L -n)
      printf "%s" "$list" | while read c chain rest; do
      if test "X$c" = "XChain" ; then
        $IP6TABLES  -t $table -F $chain
      fi
      done
      $IP6TABLES  -t $table -X
  done < /proc/net/ip6_tables_names
}


P2P_INTERFACE_WARNING=""

missing_address() {
    address=$1
    cmd=$2

    oldIFS=$IFS
    IFS="@"
    set $address
    addr=$1
    interface=$2
    IFS=$oldIFS



    $IP addr show dev $interface | grep -q POINTOPOINT && {
        test -z "$P2P_INTERFACE_WARNING" && echo "Warning: Can not update address of interface $interface. fwbuilder can not manage addresses of point-to-point interfaces yet"
        P2P_INTERFACE_WARNING="yes"
        return
    }

    test "$cmd" = "add" && {
      echo "# Adding ip address: $interface $addr"
      echo $addr | grep -q ':' && {
          $FWBDEBUG $IP addr $cmd $addr dev $interface
      } || {
          $FWBDEBUG $IP addr $cmd $addr broadcast + dev $interface
      }
    }

    test "$cmd" = "del" && {
      echo "# Removing ip address: $interface $addr"
      $FWBDEBUG $IP addr $cmd $addr dev $interface || exit 1
    }

    $FWBDEBUG $IP link set $interface up
}

list_addresses_by_scope() {
    interface=$1
    scope=$2
    ignore_list=$3
    $IP addr ls dev $interface | \
      awk -v IGNORED="$ignore_list" -v SCOPE="$scope" \
        'BEGIN {
           split(IGNORED,ignored_arr);
           for (a in ignored_arr) {ignored_dict[ignored_arr[a]]=1;}
         }
         (/inet |inet6 / && $0 ~ SCOPE && !($2 in ignored_dict)) {print $2;}' | \
        while read addr; do
          echo "${addr}@$interface"
	done | sort
}


update_addresses_of_interface() {
    ignore_list=$2
    set $1 
    interface=$1 
    shift

    FWB_ADDRS=$(
      for addr in $*; do
        echo "${addr}@$interface"
      done | sort
    )

    CURRENT_ADDRS_ALL_SCOPES=""
    CURRENT_ADDRS_GLOBAL_SCOPE=""

    $IP link show dev $interface >/dev/null 2>&1 && {
      CURRENT_ADDRS_ALL_SCOPES=$(list_addresses_by_scope $interface 'scope .*' "$ignore_list")
      CURRENT_ADDRS_GLOBAL_SCOPE=$(list_addresses_by_scope $interface 'scope global' "$ignore_list")
    } || {
      echo "# Interface $interface does not exist"
      # Stop the script if we are not in test mode
      test -z "$FWBDEBUG" && exit 1
    }

    diff_intf missing_address "$FWB_ADDRS" "$CURRENT_ADDRS_ALL_SCOPES" add
    diff_intf missing_address "$CURRENT_ADDRS_GLOBAL_SCOPE" "$FWB_ADDRS" del
}

clear_addresses_except_known_interfaces() {
    $IP link show | sed 's/://g' | awk -v IGNORED="$*" \
        'BEGIN {
           split(IGNORED,ignored_arr);
           for (a in ignored_arr) {ignored_dict[ignored_arr[a]]=1;}
         }
         (/state/ && !($2 in ignored_dict)) {print $2;}' | \
         while read intf; do
            echo "# Removing addresses not configured in fwbuilder from interface $intf"
            $FWBDEBUG $IP addr flush dev $intf scope global
            $FWBDEBUG $IP link set $intf down
         done
}

check_file() {
    test -r "$2" || {
        echo "Can not find file $2 referenced by address table object $1"
        exit 1
    }
}

check_run_time_address_table_files() {
    :
    
}

load_modules() {
    :
    OPTS=$1
    MODULES_DIR="/lib/modules/`uname -r`/kernel/net/"
    MODULES=$(find $MODULES_DIR -name '*conntrack*' \! -name '*ipv6*'|sed  -e 's/^.*\///' -e 's/\([^\.]\)\..*/\1/')
    echo $OPTS | grep -q nat && {
        MODULES="$MODULES $(find $MODULES_DIR -name '*nat*'|sed  -e 's/^.*\///' -e 's/\([^\.]\)\..*/\1/')"
    }
    echo $OPTS | grep -q ipv6 && {
        MODULES="$MODULES $(find $MODULES_DIR -name nf_conntrack_ipv6|sed  -e 's/^.*\///' -e 's/\([^\.]\)\..*/\1/')"
    }
    for module in $MODULES; do 
        if $LSMOD | grep ${module} >/dev/null; then continue; fi
        $MODPROBE ${module} ||  exit 1 
    done
}

verify_interfaces() {
    :
    echo "Verifying interfaces: enP4p1s0 lo"
    for i in enP4p1s0 lo ; do
        $IP link show "$i" > /dev/null 2>&1 || {
            log "Interface $i does not exist"
            exit 1
        }
    done
}

prolog_commands() {
    echo "Running prolog script"
    
}

epilog_commands() {
    echo "Running epilog script"
    
}

run_epilog_and_exit() {
    epilog_commands
    exit $1
}

configure_interfaces() {
    :
    # Configure interfaces
    update_addresses_of_interface "lo 127.0.0.1/8" ""
    getaddr enP4p1s0  i_enP4p1s0
    getaddr6 enP4p1s0  i_enP4p1s0_v6
    getnet enP4p1s0  i_enP4p1s0_network
    getnet6 enP4p1s0  i_enP4p1s0_v6_network
}

script_body() {
    echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter 
     echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route 
     echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects 
     echo 1 > /proc/sys/net/ipv4/conf/all/log_martians 
     echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts 
     echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses 


    # ================ IPv4


    # ================ Table 'filter', automatic rules
    # accept established sessions
    $IPTABLES -A INPUT   -m state --state ESTABLISHED,RELATED -j ACCEPT 
    $IPTABLES -A OUTPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT 
    $IPTABLES -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 
    # backup ssh access
    $IPTABLES -A INPUT  -p tcp -m tcp  -s 192.168.2.1/255.255.255.255  --dport 22  -m state --state NEW,ESTABLISHED -j  ACCEPT 
    $IPTABLES -A OUTPUT  -p tcp -m tcp  -d 192.168.2.1/255.255.255.255  --sport 22  -m state --state ESTABLISHED,RELATED -j ACCEPT 
    # drop packets that do not match any valid state and log them
    $IPTABLES -N drop_invalid
    $IPTABLES -A OUTPUT   -m state --state INVALID  -j drop_invalid 
    $IPTABLES -A INPUT    -m state --state INVALID  -j drop_invalid 
    $IPTABLES -A FORWARD  -m state --state INVALID  -j drop_invalid 
    $IPTABLES -A drop_invalid -j LOG --log-level debug --log-prefix "INVALID state -- DENY "
    $IPTABLES -A drop_invalid -j DROP






    # ================ Table 'filter', rule set Policy
    # 
    # Rule 0 (enP4p1s0)
    # 
    echo "Rule 0 (enP4p1s0)"
    # 
    # anti-spoofing rule for packets that claim to originate from opi2 but are inbound on the interface (note dynamic addressing in use) meaning they actually came from somewhere else and thus have been "spoofed" as trust worthy
    $IPTABLES -N In_RULE_0
    for i_enP4p1s0 in $i_enP4p1s0_list
    do
    test -n "$i_enP4p1s0" && $IPTABLES -A INPUT -i enP4p1s0   -s $i_enP4p1s0   -j In_RULE_0 
    done
    for i_enP4p1s0 in $i_enP4p1s0_list
    do
    test -n "$i_enP4p1s0" && $IPTABLES -A FORWARD -i enP4p1s0   -s $i_enP4p1s0   -j In_RULE_0 
    done
    $IPTABLES -A In_RULE_0  -j LOG  --log-level info --log-prefix "RULE 0 -- DENY "
    $IPTABLES -A In_RULE_0  -j DROP
    # 
    # Rule 1 (lo)
    # 
    echo "Rule 1 (lo)"
    # 
    $IPTABLES -A INPUT -i lo   -m state --state NEW  -j ACCEPT
    $IPTABLES -A OUTPUT -o lo   -m state --state NEW  -j ACCEPT
    # 
    # Rule 2 (global)
    # 
    echo "Rule 2 (global)"
    # 
    # server needs DNS to back-resolve clients IPs.
    # Even if it does not log host names during its
    # normal operations, statistics scripts such as
    # webalizer need it for reporting.
    $IPTABLES -A OUTPUT -p tcp -m tcp  -m multiport  --dports 80,443,2049,22  -m state --state NEW  -j ACCEPT
    $IPTABLES -A INPUT -p tcp -m tcp  -m multiport  --dports 80,443,2049,22  -m state --state NEW  -j ACCEPT
    $IPTABLES -A FORWARD -p tcp -m tcp  -m multiport  --dports 80,443,2049,22  -m state --state NEW  -j ACCEPT
    # 
    # Rule 3 (global)
    # 
    echo "Rule 3 (global)"
    # 
    $IPTABLES -A OUTPUT -p tcp -m tcp  --dport 9981:9982  -m state --state NEW  -j ACCEPT
    $IPTABLES -A OUTPUT -p tcp -m tcp  -m multiport  --dports 8096,8123,8096,8883,1883  -m state --state NEW  -j ACCEPT
    $IPTABLES -A INPUT -p tcp -m tcp  --dport 9981:9982  -m state --state NEW  -j ACCEPT
    $IPTABLES -A INPUT -p tcp -m tcp  -m multiport  --dports 8096,8123,8096,8883,1883  -m state --state NEW  -j ACCEPT
    $IPTABLES -A FORWARD -p tcp -m tcp  --dport 9981:9982  -m state --state NEW  -j ACCEPT
    $IPTABLES -A FORWARD -p tcp -m tcp  -m multiport  --dports 8096,8123,8096,8883,1883  -m state --state NEW  -j ACCEPT
    # 
    # Rule 4 (global)
    # 
    echo "Rule 4 (global)"
    # 
    $IPTABLES -N Cid6434X2437931.0
    $IPTABLES -A OUTPUT  -d 192.168.2.1   -m state --state NEW  -j Cid6434X2437931.0
    $IPTABLES -A Cid6434X2437931.0 -p icmp  -m icmp  --icmp-type 3  -j ACCEPT
    $IPTABLES -A Cid6434X2437931.0 -p icmp  -m icmp  --icmp-type 0/0   -j ACCEPT
    $IPTABLES -A Cid6434X2437931.0 -p icmp  -m icmp  --icmp-type 11/0   -j ACCEPT
    $IPTABLES -A Cid6434X2437931.0 -p icmp  -m icmp  --icmp-type 11/1   -j ACCEPT
    $IPTABLES -A Cid6434X2437931.0 -p tcp -m tcp  --dport 53  -j ACCEPT
    $IPTABLES -A Cid6434X2437931.0 -p udp -m udp  -m multiport  --dports 68,67,53,123  -j ACCEPT
    # 
    # Rule 5 (global)
    # 
    echo "Rule 5 (global)"
    # 
    for i_enP4p1s0 in $i_enP4p1s0_list
    do
    test -n "$i_enP4p1s0" && $IPTABLES -A INPUT -p tcp -m tcp  -s $i_enP4p1s0   --dport 1514:1515  -m state --state NEW  -j ACCEPT 
    done
    $IPTABLES -A OUTPUT -p tcp -m tcp  --dport 1514:1515  -m state --state NEW  -j ACCEPT
    # 
    # Rule 6 (global)
    # 
    echo "Rule 6 (global)"
    # 
    $IPTABLES -A INPUT -p tcp -m tcp  -s 192.168.2.0/24   --dport 8200:8300  -m state --state NEW  -j ACCEPT
    $IPTABLES -A FORWARD -p tcp -m tcp  -s 192.168.2.0/24   --dport 8200:8300  -m state --state NEW  -j ACCEPT
    # 
    # Rule 7 (global)
    # 
    echo "Rule 7 (global)"
    # 
    $IPTABLES -N RULE_7
    for i_enP4p1s0 in $i_enP4p1s0_list
    do
    test -n "$i_enP4p1s0" && $IPTABLES -A OUTPUT  -d $i_enP4p1s0   -j RULE_7 
    done
    $IPTABLES -A INPUT  -j RULE_7
    $IPTABLES -A RULE_7  -j LOG  --log-level info --log-prefix "RULE 7 -- DENY "
    $IPTABLES -A RULE_7  -j DROP
}

ip_forward() {
    :
    echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
}

reset_all() {
    :
    reset_iptables_v4
}

block_action() {
    reset_all
}

stop_action() {
    reset_all
    $IPTABLES  -P OUTPUT  ACCEPT
    $IPTABLES  -P INPUT   ACCEPT
    $IPTABLES  -P FORWARD ACCEPT
}

check_iptables() {
    IP_TABLES="$1"
    [ ! -e $IP_TABLES ] && return 151
    NF_TABLES=$(cat $IP_TABLES 2>/dev/null)
    [ -z "$NF_TABLES" ] && return 152
    return 0
}
status_action() {
    check_iptables "/proc/net/ip_tables_names"
    ret_ipv4=$?
    check_iptables "/proc/net/ip6_tables_names"
    ret_ipv6=$?
    [ $ret_ipv4 -eq 0 -o $ret_ipv6 -eq 0 ] && return 0
    [ $ret_ipv4 -eq 151 -o $ret_ipv6 -eq 151 ] && {
        echo "iptables modules are not loaded"
    }
    [ $ret_ipv4 -eq 152 -o $ret_ipv6 -eq 152 ] && {
        echo "Firewall is not configured"
    }
    exit 3
}

# See how we were called.
# For backwards compatibility missing argument is equivalent to 'start'

cmd=$1
test -z "$cmd" && {
    cmd="start"
}

case "$cmd" in
    start)
        log "Activating firewall script generated Sat Jan 18 08:48:04 2025 by acas"
        check_tools
         prolog_commands 
        check_run_time_address_table_files
        
        load_modules " "
        configure_interfaces
        verify_interfaces
        
         reset_all 
        
        script_body
        ip_forward
        
        epilog_commands
        RETVAL=$?
        ;;

    stop)
        stop_action
        RETVAL=$?
        ;;

    status)
        status_action
        RETVAL=$?
        ;;

    block)
        block_action
        RETVAL=$?
        ;;

    reload)
        $0 stop
        $0 start
        RETVAL=$?
        ;;

    interfaces)
        configure_interfaces
        RETVAL=$?
        ;;

    test_interfaces)
        FWBDEBUG="echo"
        configure_interfaces
        RETVAL=$?
        ;;



    *)
        echo "Usage $0 [start|stop|status|block|reload|interfaces|test_interfaces]"
        ;;

esac

exit $RETVAL