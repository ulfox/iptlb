# IPTLB

Simple IPTables loadbalancer app

## Description

The app provides 3 options

### Rules Backend (default)

Option: `-rules-backend=[client/proxy/server]` 

This option is by default "client". Set to `client` if you want to apply the rules in the client side. Set to `proxy` if you want to apply the rules in an intermediate server, and last set to `server` if you want to apply the rules in the server side.

The difference with the above 3 modes is the chain where we apply the jump before we apply our DNAT.
- client: OUTPUT
- proxy: PREROUTING
- server: INPUT

When we use "client", we are essentially applying a LB logic in the client host.

### Source Addr

Option: `-src-addr`

The source socket ipv4 address that you want to use as a loadbalancing ingress. If you are applying rules in the client side the IPV4 address could be any address. Even non-routable addresses will work because the rules will capture the OUTPUT chain (before it leaves the gw)

### Destination Addresses

Option: `-dest-addr`

This is a comma-separated string of destination ipv4 socket addresses (e.g. **ipv4_1:port1,ipv4_2:port2,...**). The destinations rules will have a random probability (Same logic as that used in kubernetes services) with the last rule being always 100% probable.

For example if we have 4 destination endpoints, then the probability will be as follows
- First endpoint 1/4 chance
- Second endpoint 1/3 chance
- Third endpoint 1/2 chance
- Last, always

## Example

Locally I have a 10.0.1.x network (with Host IP 10.0.1.4) and a service listening to port 8080. On this example I will use a different network (10.100.0.10) with different port (8081) as my source, the destination will be the actual host `10.0.1.4:8080` 

Actual endpoint
- 10.0.1.4:8080

Ingress endpoint
- 10.100.0.10:8081 // This is not routable in my network but it will work since we are going to capture the packets in the OUTPUT chain and apply DNAT rules for 10.0.1.4

```bash
$> sudo go run main.go -src-addr=10.100.0.10:8081 -dest-addr=10.0.1.4:8080
INFO[0000] Initiating                                    Component=main Prog=iptlb
INFO[0000] Chain IPT_NAT_LB found                        Component=createTable Prog=iptlb
INFO[0000] Enabled logging to chain IPT_NAT_LB           Component=createTable Prog=iptlb
INFO[0000] Rule: -p tcp -d  10.100.0.10 --dport 8081 -j IPT_NAT_LB exists  Component=jumpToCustomNAT Prog=iptlb
INFO[0000] Chain IPT_FILTER_LB found                     Component=createTable Prog=iptlb
INFO[0000] Enabled logging to chain IPT_FILTER_LB        Component=createTable Prog=iptlb
INFO[0000] Rule: -p tcp -d 10.0.1.4 --dport 8080 -j IPT_FILTER_LB exists  Component=jumpToCustomFilter Prog=iptlb
```

Doing a curl on the `10.100.0.10:8081`

```bash
$> curl https://10.100.0.10:8081 -kLI
HTTP/2 404 
content-type: text/plain; charset=utf-8
x-content-type-options: nosniff
content-length: 19
date: Fri, 24 Dec 2021 08:12:46 GMT

```
