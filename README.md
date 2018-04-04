# core-network [![Build Status](https://travis-ci.org/me-box/core-network.svg?branch=master)](https://travis-ci.org/me-box/core-network)
A system component in databox managing container-to-container and container-to-external communications

### Operation Models
#### At the start of Databox:
1. CM, arbiter, core-network will be put on a network `databox-system-net`
2. CM calls on core-network to identify itself as a privileged entity, then CM is authorized to resolve all the other components that core-network knows of and make connections with them

#### When an app or driver is requested to be installed:
1. A dedicated network is created, core-network then gets attached to it, and by default external access is disallowed on this network
2. After parsing SLA, CM gathers all the entities that this component would like to communicate with (arbiter, and its dependent stores, datasources etc.), and call on core-network to enable these, which includes being able to resolve host names and make connections with previously resolved IP addresses
3. When CM starts the app/driver and its dependent stores, their DNS servers will be pointed to core-network

#### When an app/driver/store is requested to be removed:
1. CM calls on core-network to disable all the communications, giving the being removed service name and its IP address. This mainly helps core-network to recollect resources and delete un-usuful states
1. CM checks if this is the last component on its dedicated network, if so, remove the network, if not, this network will be kept and reusued when a user possibly wants to reinstall a related service

### Internals
core-network oprates on IP packet, for all the other L4 traffic, it only concerns itself with DNS queries.

All the control policies are stored within two data structures:
```
transport: Set of (src_ip, dst_ip')
resolve:   Map from src_ip to (host name, dst_ip') list
```
When a packet comes in from an interface, its (src_ip, dst_ip') pair is checked against `transport`, only existed pairs are allowed to move on, otherwise the packet will get dropped. And when a DNS query comes in, the src_ip of the query and the name it wants to resolve are extracted, then it tries to find a dst_ip' from `resolve`.

Another point worth mentioning is that all the `src_ip`s are the IP addresses that currently used by containers, and almost all the `dst_ip'`s are spoofed by core-network on each interface within the same subnet as with associated `src_ip`s.

When CM calls on core-network to enable communication for a pair of host names, core-network firstly tries to resolve those to (src_ip, dst_ip). If they are coming from the same subnet, like driver and its dependent store, only `resolve` will be updated to contain these new infomation. Since core-network serves as the DNS server for them, when driver wants to talk to its store, a DNS query will be expected to come up in core-network, and core-network could lookup `resolve` to return the IP of the store. When src_ip and dst_ip are from different subnets, like app and one of its datasources, core-network will spoof dst_ip' and src_ip' on both of those two networks, and `transport` will be updated with (src_ip, dst_ip') and also (dst_ip, src_ip'), so that traffic could come back and forth from both sides. `resolve` will also be updated accrodingly, DNS requires from both sides will be replied with spoofed addresses within their same subnets. This also implies that there is a NAT-like module which is in charge of translating from (src_ip, dst_ip') to (src_ip', dst_ip) before sending the packet out.

So a container can't communicate with an entity which it doesn't declare explicitly in the manifest, cause no such infomation reside in `resolve` and `NXDOMAIN` will be returned. It can't use an IP directly either, cause everything is constraint to happen locally, and all the contactable IPs on the local subnet are either its dependent stores, or are spoofed and controlled by core-network.


### API exposed
All of the following calls are intended to be invoked only by core-container-manager, and caller is authenticated by a key.
```
POST /privileged
input: {"src_ip": <string>}
```
`src_ip` is a privileged source IP. Any DNS queries or communications from this IP will be served. CM calls on this when it starts up.

```
POST /connect
input: {"name":<string>, "peers":[<string>]}
```
`name` is the service's host name which CM wants to enable communications for, `peers` is an array of peer host names that this service may want connmunicate with.

```
POST /disconnect
intput: {"name":<string>, "ip":<string>}
```
`name` is the service about to be removed, and `ip` is its IP address. core-container uses these to delete related states.


```
POST /restart
intput: {"name":<string>, "old_ip":<string>, "new_ip":<string>}
```
`name` is the restarted service, and `old_ip` is its IP address before restart, `new_ip` is the new IP address after retart. core-network updates the policies accroding to this change.

```
GET /status
```
This returns a string `'active'`.
