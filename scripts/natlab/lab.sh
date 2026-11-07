#!/usr/bin/env bash
# Reproducible NAT lab on Linux network namespaces (needs root, iproute2, iptables). No packet leaves the machine.
#
#   frrelay  20.20.20.10   frP1-3 21/22/23.x.x.10   public relay / public peers (one /4 segment, 4 distinct first octets)
#   frnatA   wan 20.20.20.2   lan 192.168.1.1  NAT router A     -> frA  192.168.1.10
#   frnatB   wan 20.20.20.3   lan 192.168.2.1  NAT router B     -> frB  192.168.2.10
#   frL1/frL2 10.201.0.1/.2                    plain LAN (no NAT, multicast on) for mDNS
#
# usage: lab.sh up | down | nat <frnatA|frnatB> <cone|symmetric> | upnp <frnatA|frnatB> start|stop
set -euo pipefail
PUB=20.20.20
NS="frrelay frP1 frP2 frP3 frnatA frnatB frA frB frL1 frL2"

ns() { local n=$1; shift; ip netns exec "$n" "$@"; }

mk() { ip netns add "$1"; ns "$1" ip link set lo up; }

# attach <bridge> <ns> <cidr>: veth from a bridge into a namespace, named eth0 there
attach() {
  local br=$1 n=$2 cidr=$3 port="b-$2"
  ip link add "t-$n" type veth peer name "$port"
  ip link set "t-$n" netns "$n" name eth0
  ip link set "$port" master "$br"; ip link set "$port" up
  ns "$n" ip addr add "$cidr" dev eth0; ns "$n" ip link set eth0 up
}

# wire <nsA> <ifA> <cidrA> <nsB> <ifB> <cidrB>: point-to-point veth
wire() {
  ip link add "w-$1" type veth peer name "w-$4"
  ip link set "w-$1" netns "$1" name "$2"; ip link set "w-$4" netns "$4" name "$5"
  ns "$1" ip addr add "$3" dev "$2"; ns "$1" ip link set "$2" up
  ns "$4" ip addr add "$6" dev "$5"; ns "$4" ip link set "$5" up
}

nat() {
  local r=$1 mode=$2
  ns "$r" iptables -t nat -F POSTROUTING
  # cone: Linux keeps the source port when it can, so the mapping does not depend on the destination (like a typical home router).
  # symmetric: --random picks a fresh port per flow, so a peer cannot predict the port another peer will see.
  if [ "$mode" = symmetric ]; then ns "$r" iptables -t nat -A POSTROUTING -o wan0 -j MASQUERADE --random
  else ns "$r" iptables -t nat -A POSTROUTING -o wan0 -j MASQUERADE; fi
}

router() { # router <ns> <wanCIDR> <lanCIDR> <host> <hostCIDR>
  mk "$1"; mk "$4"
  attach frpub "$1" "$2"; ns "$1" ip link set eth0 name wan0
  wire "$1" lan0 "$3" "$4" eth0 "$5"
  ns "$4" ip route add default via "${3%/*}"
  ns "$1" sysctl -qw net.ipv4.ip_forward=1
  # a normal home-router firewall: LAN may go out, the internet may only answer
  ns "$1" iptables -P FORWARD DROP
  ns "$1" iptables -A FORWARD -i lan0 -j ACCEPT
  ns "$1" iptables -A FORWARD -i wan0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  nat "$1" cone
}

up() {
  down 2>/dev/null || true
  ip link add frpub type bridge; ip link set frpub up
  ip link add frlan type bridge mcast_snooping 0; ip link set frlan up
  mk frrelay; attach frpub frrelay "$PUB.10/4"
  router frnatA "$PUB.2/4" 192.168.1.1/24 frA 192.168.1.10/24
  router frnatB "$PUB.3/4" 192.168.2.1/24 frB 192.168.2.10/24
  # the NATed hosts reach the internet only through their router; frrelay needs no route (same /24)
  # three more public peers in other /8s: AutoNAT v2 only confirms an address after 4 dial-backs from 4 different first octets
  local i=1; for o in 21 22 23; do mk "frP$i"; attach frpub "frP$i" "$o.$o.$o.10/4"; i=$((i+1)); done
  mk frL1; mk frL2
  attach frlan frL1 10.201.0.1/24; attach frlan frL2 10.201.0.2/24
  for n in frL1 frL2; do ns "$n" ip route add 224.0.0.0/4 dev eth0; done
}

down() {
  upnp frnatA stop 2>/dev/null || true; upnp frnatB stop 2>/dev/null || true
  for n in $NS; do ip netns del "$n" 2>/dev/null || true; done
  ip link del frpub 2>/dev/null || true; ip link del frlan 2>/dev/null || true
}

# miniupnpd (nftables backend) on the router's LAN side, mapping the WAN side. 20.20.20.x is not RFC1918, so miniupnpd
# accepts it as an external address. Policy stays with the iptables rules above; a mapping makes the flow a DNAT one,
# and the router lets exactly those through, as a home router does.
upnp() {
  local r=$1 act=$2 conf="/tmp/frenet-upnp-$1.conf" pid="/tmp/frenet-upnp-$1.pid"
  if [ "$act" = stop ]; then
    [ -f "$pid" ] && kill "$(cat "$pid")" 2>/dev/null || true
    rm -f "$pid" "$conf"; ns "$r" nft delete table inet filter 2>/dev/null || true
    ns "$r" iptables -D FORWARD -i wan0 -m conntrack --ctstate DNAT -j ACCEPT 2>/dev/null || true
    return 0
  fi
  cat >"$conf" <<EOF
ext_ifname=wan0
listening_ip=lan0
enable_upnp=yes
enable_pcp_pmp=no
secure_mode=no
system_uptime=yes
uuid=00000000-0000-4000-8000-00000000000$([ "$r" = frnatA ] && echo 1 || echo 2)
EOF
  ns "$r" nft -f - <<EOF
table inet filter {
  chain forward { type filter hook forward priority 0; policy accept; jump miniupnpd; }
  chain miniupnpd { }
  chain prerouting { type nat hook prerouting priority -100; policy accept; jump prerouting_miniupnpd; }
  chain postrouting { type nat hook postrouting priority 100; policy accept; jump postrouting_miniupnpd; }
  chain prerouting_miniupnpd { }
  chain postrouting_miniupnpd { }
}
EOF
  ns "$r" iptables -I FORWARD -i wan0 -m conntrack --ctstate DNAT -j ACCEPT
  ns "$r" miniupnpd -f "$conf" -P "$pid"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  nat) nat "$2" "$3" ;;
  upnp) upnp "$2" "$3" ;;
  *) echo "usage: $0 up|down|nat <router> <cone|symmetric>|upnp <router> start|stop" >&2; exit 2 ;;
esac
