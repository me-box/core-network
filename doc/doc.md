### Interface Management
During the runtime of `core-network`, for each virtualized network interface of the
container, there is a corresponded `Intf.t` value. It contains information such
as the interface name and the network address, it also has some handles to i/o streams.
All of these values will be gathered in and managed by a `Interfaces.t` value.
#### traffic flow
Upon creation or removal of an interface, the `Intf.t` value will be registered or deregistered with `Interfaces.t`.
When packets are avaiable from an input stream of an interface, it's `Interfaces.t` that extracts them out and calls on
dispatch function with these packets. All interfaces share the same dispatch function, where control policies are checked
and NAT is done. If there are packets to forward on, `Interfaces.t` takes over them, figures out which interface's
output stream to push these packets in, and then let a `Intf.t` values handles the output of a packet.
#### related code snippets
- [Intf.t]
- [Interfaces.register_intf]
- [Junction.Dispatcher.dispatch]
- [Interfaces.to_push].

[Intf.t]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/intf.ml#L19-L31
[Interfaces.register_intf]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/interfaces.ml#L108-L132
[Junction.Dispatcher.dispatch]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/junction.ml#L222-L242
[Interfaces.to_push]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/interfaces.ml#L75-L81


### Fake Addresses
Using fake addresses is a result of realizing the control functionalities while sustaining constraints posed by docker networkings.
The control consists of two parts: i) a service should only be able to resolve domain names claimed in the manifest,
plus names of needed system components (container-manager and arbiter for all the cases, some also includes
export-service); ii) a service shouldn't be able to communicate with any other service by fabricating a packet with self-learned
or hard-coded destination IP address. To realize these two points, `core-network` should be able to intercept all DNS
requests and control the returned DNS reponses, for the second point `core-network` should be able to see each of the packet in a flow,
and check its validity by examing its destination address.
The first part is easily achieved, by pointing service's DNS server to `core-network` using container options.
But the second part is not. It's hindered by some constraints from docker networking.
Databox is running under swarm mode. Services started in swarm mode can't have `NET_ADMIN`
capability, which is needed to set the gateway or modifying any routing rule. Although we could let `core-network` to actively eavesdrop
all traffic happening in a local docker network, but it still has no means to prevent a packet from sending out to an un-authorized
service, either inside or outside Databox.

And the solution in `core-network` comes with using fake addresses.
As `core-network` controls the name resolving for services, it returns a fake address in the local docker network for
an authorzied DNS request, before a DNS response containing the fake address is returned, a mapping between the fake address
and `core-network`'s MAC address is inserted in the ARP table, so that it's guranteed that `core-network` could receive all the packets
destined to that returned fake address later. Basically, it's a combination of DNS spoofing and ARP spoofing.
As communications are bi-directional, another fake address is also allocated together in the network where the requested service attaches.
When a packet with any of these two fake addresses comes in `core-network`, it knows how to replace the source/destination pair in the
specific packet.
#### related code snippets
- in databox/core-container-manager/src/container-manager.js, usage of argument `network` in function [appConfig], [driverConfig], and [storeConfig]
- [Intf.fake_ip_op]
- [Interfaces.acquire_fake_dst]
- invocations of [Interfaces.acquire_fake_dst] and [Nat.add_rule] in [Policy.process_pair_connect], [Policy.connect_for_privileged_exn].

[appConfig]: https://github.com/me-box/core-container-manager/blob/4ced8c8891832a936bc6fe4c3a3107ffbafa548c/src/container-manager.js#L441-L503
[driverConfig]: https://github.com/me-box/core-container-manager/blob/4ced8c8891832a936bc6fe4c3a3107ffbafa548c/src/container-manager.js#L388-L439
[storeConfig]: https://github.com/me-box/core-container-manager/blob/4ced8c8891832a936bc6fe4c3a3107ffbafa548c/src/container-manager.js#L505-L554
[Intf.fake_ip_op]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/intf.ml#L97-L121
[Interfaces.acquire_fake_dst]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/interfaces.ml#L95-L100
[Nat.add_rule]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/nat.ml#L25-L35

### Control Policies
#### name resolving and packet forward
All the control policies are stored in a single value of the type `Policy.t`. This value contains various fields
where the actual control poicies are stored.
As mentioned above, the traffic control in `core-network` involves two parts. The name resolving part is represented
as a map, between the source IP address of a DNS request, and an association list, where the key is authorized service name,
and the value is a fake address generated during policy configuration. And the packet forwarding part is represented
as a set. The type of the element of such a set is IP address pair. These pairs represent the whole set of authorized communication
entities. Note that the destination addresses in those pairs are all fake addresses. And the translation of addresses
in a single packet is taken care of by `Nat` module, and `Policy.t` has a reference to `Nat.t` as a separate field.
#### policy configuration
`core-network` exposes a couple of RESTful endpoints to enable configuration of control polices,
these endpoints are defined in module `Junciton.Local`. Effectively, only `container-manager` is capable
of accessing these endpoints, this is guranteed by checking the `X-API-KEY` HTTP header of requests for these endpoints. The arguments of these
endpoints are expressed in terms of service names. As `core-network` is connected to all the docker networks to which apps and drivers are
connected, it has enough information to figure out the actual network addresses of the services that're given as arguments, this is done by
querying the embeded DNS server that is found running in every Docker container.
Once `core-network` has the service names and their addresses, it could insert new mappings or add new element to related fields of `Policy.t`,
thus completing the configuration.

When an app or driver is to be installed, its SLA is generated and parsed in `container-manager`, all the entities that this service is going to
communicate with are extracted. With these entities' names and its own name, the endpoint `/connect` of `core-network` is called. The handler
of this endpoint is called asynchronously. This is necessary, as the handler involves firstly resolving these services' names.
However, at this stage, the requested service itself (and its dependent stores if there are any) hasn't been installed.
So the resolving part is put into a loop, which retries the resolving upon timeout until a limited number of times.
Calling the handler asynchronously allows the control flow to return to the point of actually installing the requested service and its dependent stores.
After they are installed, the name resolving could then succeed returning their network addresses, and the policy configuration could
continue and finally complete. Upon completion of the handler, the service could start making network communications as it needs.
From another point of view, the invocation of `/connect` endpoint is more like to put `core-network` in a polling state rather than doing any real policy configuration.
Once the services are detected installed and running, associated policies are yet to be configured.
#### privileged entites
There are essentially two privileged entities, `container-manager` and `arbiter`. `container-manager` is privileged in the sense that it could
resolve any of the service names that are known to `core-network`, and it could communicate with any of them too. This is the case because
if an app or driver implements a web UI, `container-manager` would need a way to access it. Whether or not an app/driver
implements a web UI is not specified in the manifest and could not be known to `core-network` beforehand. Making `container-manager` privileged
is the flexibility needed on top of the configuration-before-installation scheme.
This is implemented by `container-manager` submitting its own IP address to `core-network` on service start. Afterwards, if a DNS request
is considered to be unauthorized according to existing policies but the source IP address of such a request matches the submitted one, the
request is known from `container-manager` and would then be fulfilled, and related polices are also configured.

Another privileged entity is `arbiter`. As each installed service needs to communicate with `arbiter`
before doing any acutal work, it is privileged in the sense that any resolving request
for `arbiter` would be allowed, and in the handler of `/connect` metioned above, if the service name pair includes `arbiter`, this pair is skipped.
The related policies are added only when the communication actually happens.
#### related code snippets
- [Policy.t]
- [Policy.is_authorized_transport]
- [Policy.is_authorized_resolve]
- [Junction.Local]
- function [auth_middleware] in Server.Make
- [Dns_service.ip_of_name] and its invocations in [Policy.process_pair_connect], [Policy.connect_for_privileged_exn]
- function [connectEndpoints] in databox/core-container-manager/src/lib/databox-network-helper.js,
and its [invocation] in databox/core-container-manager/src/container-manager.js
- [Policy.connect].

[Policy.t]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/policy.ml#L25-L32
[Policy.is_authorized_transport]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/policy.ml#L170-L171
[Policy.is_authorized_resolve]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/policy.ml#L209-L217
[Policy.connect]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/policy.ml#L119-L126
[Junction.Local]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/junction.ml#L15-L211
[auth_middleware]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/server.ml#L74-L94
[Dns_service.ip_of_name]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/dns_service.ml#L44-L57
[connectEndpoints]: https://github.com/me-box/core-container-manager/blob/4ced8c8891832a936bc6fe4c3a3107ffbafa548c/src/lib/databox-network-helper.js#L54-L84
[invocation]: https://github.com/me-box/core-container-manager/blob/4ced8c8891832a936bc6fe4c3a3107ffbafa548c/src/container-manager.js#L187
[Policy.process_pair_connect]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/policy.ml#L86-L116
[Policy.connect_for_privileged_exn]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/policy.ml#L173-L190


### Service bootstrapping
It starts from [databox/databox-start] script. At first, network `databox-system-net` is created,
then the service `core-network` is started and attached to this network. This network is the same one on which `container-manager`, `arbiter`,
and `export-service` are attached too.

The entry point of `core-network` is the main function in module `bin/core_network.ml`. In this main
function, a `monitor` thread is started first, then a `junction` thread.
`monitor` thread is responsible for monitoring the changes of network interfaces of the container.
If a new interface is created, or an old interface is removed, the interface name and assigned network address are delivered to
the `junction` thread. In the `junction` thread, there is the reference to `Interfaces.t` value. Upon receiving an interface change event
from `monitor`, the related interface could be registered or deregistered with `Interfaces.t`

At the start of Databox, before any app or driver is installed, `core-network` has two interfaces, `eth0` and `eth1`. `monitor` could detects their
existence, and they are registered with `Interfaces.t` too. `eth0` is the interface on `databox-system-net`, so it is the only interface
that the policy configuration web service of `core-network` acutally listens on. The other one `eth1` is on `docker_gwbridge`.
The `docker_gwbridge` network is used to provide external connectivity for any containers connected to an `overlay` network,
it is created when a swarm is started on a host or a host joins an existing swarm. If a driver needs to communicate with external endpoints
in the Internet later on, it's `eth1` and `docker_gwbridge` that the traffic would travel through.

As mentioned in [privileged entities](#privileged-entities) section,
the identification of `container-manager` also happens at this stage. But there is a problem:
`container-manager` needs to know `core-networks`'s address to submit its own address, but before this happends, `core-network` wouldn't
know `container-manager`'s privileged status, thus it would effectively refuse the resolving request from `container-manager` for its own name.
This is worked around by making network `databox-system-net` privileged for a short period of time during start. So any DNS request coming in
through `eth0` is considered authorized during this phase.
After `container-manager` coming in and identifying itself, the privileged status of `databox-system-net` is revoked, only leaves
`container-manager` and `arbiter` as privileged entiites.
#### related code snippets
- [Core_network.main]
- function [junction_lp] in Junction.create
- function [add_privileged] in Junction.Local
- function [connect] in databox/core-container-manager/src/container-manager.js.

[databox/databox-start]: https://github.com/me-box/databox/blob/ab44d422791ab3760b2dc01aeeda1179f14567df/databox-start#L192-L194
[Core_network.main]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/bin/core_network.ml#L16-L25
[junction_lp]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/junction.ml#L269-L296
[add_privileged]: https://github.com/me-box/core-network/blob/bd1bc85710d3ead44fdd956d633b9ef38f26fa08/lib/junction.ml#L174-L191
[connect]: https://github.com/me-box/core-container-manager/blob/4ced8c8891832a936bc6fe4c3a3107ffbafa548c/src/container-manager.js#L728-L738
