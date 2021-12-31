# IPTLB

Simple IPTables loadbalancer app

## Description

IPTLB can be configured to apply rules that capture the traffic to a specific socket ipv4 address and redirect the packets to different addresses. When multiple addresses are given as destinations, a random loadbalance logic will be applied to split the traffic between the destinations.

## Options

### Run

Option: `-run`

IPTLB will not make any change to the iptables unless **-run** has been provided. Without run we essentially write the profile in the local state which we can use on the future by adding the run flag. This option can be used with **-use-state** && **-state-file=/path/to/state.db** to read a local state file and apply it.

### Rules Backend (default)

Option: `-rules-backend=[client/proxy/server]` 

This option is by default "client". Set to `client` if you want to apply the rules in the client side. Set to `proxy` if you want to apply the rules in an intermediate server, and last set to `server` if you want to apply the rules in the server side.

The difference with the above 3 modes is the chain where we apply the jump before we apply our DNAT.
- client: OUTPUT
- proxy: PREROUTING
- server: INPUT

When we use "client", we are essentially applying a LB logic in the client host.

### (UNIQUE) Source Addr

Option: `-src-addr`

The source socket ipv4 address that you want to use as a loadbalancing ingress. If you are applying rules in the client side the IPV4 address could be any address. Even non-routable addresses will work because the rules will capture the OUTPUT chain (before it leaves the gw)

**Note-1**: The source address is the address we are going to use to capture the packet stream that we want to redirect. This option is unique across all profiles (see profile option). We can not use the same source address because the first jump that will satisfy the condition will terminate the nat evaluation. Due to that reason, having multiple -src-addr with different destinations does not work. IPTLB allows to check the protocol also (see protocol option). While the protocol option can differentiate the jump rule, the functionality is not yet implemented, so for now a -src-addr=x:y is global and can not be used a second time. In the future we will allow this for different protocols

### Destination Addresses

Option: `-dest-addr`

This is a comma-separated string of destination ipv4 socket addresses (e.g. **ipv4_1:port1,ipv4_2:port2,...**). The destinations rules will have a random probability (Same logic as that used in kubernetes services) with the last rule being always 100% probable.

For example if we have 4 destination endpoints, then the probability will be as follows
- First endpoint 1/4 chance
- Second endpoint 1/3 chance
- Third endpoint 1/2 chance
- Last, always

### Profile

Option: `-profile=profileName`

IPTLB uses profiles to keep track and apply rules for different **-src-addr**. For example we can have 1 profile to capture traffic from **-src-addr=someIPV4-0:somePort-0** and redirect it to a list of hostsA, and a different profile that captures traffic from **-src-addr=someIPV4-1:somePort-1** and redirects the traffic to a list of different hosts or even the same

### Reset

Option: `-reset`

Once a profile have been created (written to local state) and applied (actual iptable chains and rules created), we can not change that profile without adding **-reset**. Reset essentially allows you to do an update on the rules and profile. This works as follows:
- IPTLB loads the profile from the state
- Removes rules & chains for the specific profile
- Writes the new input to local state
- Creates new chain and inputs

### Delete

Option: `-delete`

We can remove a profile and the related chains and rules by applying **-delete** flag. 
- IPTLB loads the profile from the state
- Removes rules & chains for the specific profile
- Deletes profile from local state

### State Path

Option: `-state-file=/path/to/state.db`

This option allows us to instruct IPTLB to write state to a different location (**Default: ./local/state.db**)

**Note**: If you use this option to create profiles and apply them, then you need to re-use it if you want to make changes or delete the profiles. If you do not pass the option the second time or some time later in the future, IPTLB will not be able to see the changes that were made on older invocations.

### Chain Logging

Option: `-log-custom-chain`

With this option we enable verbose logging for the created chains and jump rules. The logs will appear in **dmesg**. You can control the log verbosity by using the **-log-level=N** option (see option below)

### Log Level

Option: `-log-level=N`

The log level for the iptable rules (**Default: 4**). This requires **-log-custom-chain** enabled or it will not do anything.


### Protocol

Option: `-protocol=protocol`

We can control the protocol that will be used to filter the NAT jump rules (**Default: tcp**).

### Use State

Option: `-use-state`

This option has only one usage, to instruct IPTLB to use the profiles locally. We need to also provide the **-run** option to apply the local state in the iptables

**Note**: Incompatible with **-src-addr** ||&& **-dest-addr**

## Example

### Create profile
Locally I have a 10.0.1.x network (with Host IP 10.0.1.4) and a service listening to port 8080. On this example I will use a different network (10.100.0.10) with different port (8081) as my source, the destination will be the actual host `10.0.1.4:8080` 

Actual endpoint
- 10.0.1.4:8080

Ingress endpoint
- 10.100.0.10:8081 // This is not routable in my network but it will work since we are going to capture the packets in the OUTPUT chain and apply DNAT rules for 10.0.1.4

```bash
$> sudo ./iptlb -run -profile=test -log-custom-chain -src-addr=10.100.0.10:8081 -dest-addr=10.0.1.4:8080
INFO[0000] Initiating                                    Component=main Prog=iptlb
INFO[0000] map[]                                         Component=main Prog=iptlb
INFO[0000] db operator initiated                         Component=main Prog=iptlb
INFO[0000] Inputs validated successfuly                  Component=Operator Stage=Configure
INFO[0000] Chain [IPTLB_NAT_TEST] on table [nat] does not exist. Creating...  Stage=createChain
INFO[0000] Enabled logging to chain IPTLB_NAT_TEST       Stage=createChain
INFO[0000] [Append] Rule: [-p tcp -d 10.100.0.10 --dport 8081 -m statistic --mode random --probability 1.00000 -j DNAT --to-destination 10.0.1.4:8080] on table[nat]/chain[IPTLB_NAT_TEST]  Stage=AddRule
INFO[0000] [Append] Rule: [-j RETURN] on table[nat]/chain[IPTLB_NAT_TEST]  Stage=AddRule
INFO[0000] Done configuring table[nat]/chain[IPTLB_NAT_TEST]  Stage=NATLBRules
INFO[0000] [Insert] Rule: [-p tcp -d 10.100.0.10 --dport 8081 -j IPTLB_NAT_TEST] at [1] on table[nat]/chain[OUTPUT]  Stage=InsertRule
INFO[0000] [Insert] Rule: [-d 10.100.0.10 -p tcp -j LOG --log-prefix IPTLB:OUTPUT:ACCEPT: --log-level 4] at [1] on table[nat]/chain[OUTPUT]  Stage=InsertRule
INFO[0000] Done configuring profile [test]               Stage=AddProfile

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

### View state file

**Note**: We can change the statefile manually only when have not applied it. If we make changes manually after we have applied it with **-run** then IPTLB probably will not delete/update old rules related with the change.

```bash
$> sudo cat local/state.db 
test:
  destination:
  - 10.0.1.4:8080
  logEnabled: true
  logLevel: "4"
  protocol: tcp
  rulesBackend: client
  source: 10.100.0.10:8081
```

### Delete profile

We can delete a profile by issuing:

```bash
$> sudo ./iptlb -run -profile=test --delete
INFO[0000] Initiating                                    Component=main Prog=iptlb
INFO[0000] map[]                                         Component=main Prog=iptlb
INFO[0000] db operator initiated                         Component=main Prog=iptlb
WARN[0000] Delete has been enabled. Deleting rules from profile [test]  Component=Operator Stage=Configure
INFO[0000] [Deleted] Rule: [-p tcp -d 10.100.0.10 --dport 8081 -m statistic --mode random --probability 1.00000 -j DNAT --to-destination 10.0.1.4:8080] table[nat]/chain[IPTLB_NAT_TEST]  Stage=RemoveRule
INFO[0000] [Deleted] Rule: [-j RETURN] table[nat]/chain[IPTLB_NAT_TEST]  Stage=RemoveRule
INFO[0000] Done configuring table[nat]/chain[IPTLB_NAT_TEST]  Stage=NATLBRules
INFO[0000] [Deleted] Rule: [-p tcp -d 10.100.0.10 --dport 8081 -j IPTLB_NAT_TEST] table[nat]/chain[OUTPUT]  Stage=RemoveRule
INFO[0000] [Deleted] Rule: [-d 10.100.0.10 -p tcp -j LOG --log-prefix IPTLB:OUTPUT:ACCEPT: --log-level 4] table[nat]/chain[OUTPUT]  Stage=RemoveRule
INFO[0000] Done cleaning profile [test]                  Stage=DeleteProfile
```
