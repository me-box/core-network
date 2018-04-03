### Interface Management
During the runtime of `core-network` service, each virtualized network interface of the
service container has a corresponded value of type `Intf.t`. It contains information such
as the interface name and the network address, and also has some handles to i/o streams.
All of these values will be gathered in and managed by a `Interfaces.t` value.
##### traffic flow
Upon creation or removal of an interface, the `Intf.t` value will be registered or deregistered with `Interfaces.t`.
When packets are avaiable from an input stream of an interface, it's `Interfaces.t` that extracts them out and calls on
dispatch functions with these packets. All interfaces share the same dispatch function, where control policies are checked
and NAT is done. If there are packets to forward on, `Interfaces.t` takes over them, figures out which interface's
output stream to push these packets in, and let a `Intf.t` values handles the output of a packet.
Related code blocks: Intf.t, Interfaces.register_intf, Junction.Dispatcher.dispatch, Interfaces.to_push.

### Fake Addresses
Using fake addresses is a result of realizing the control functionalities while sustaining constraints posed by docker networkings.
The control consists of two parts: i) a service should only be able to resolve domain names claimed in the manifest,
plus names of needed system components (container-manager and arbiter for all the cases, some also includes
export-service); ii) a service shouldn't be able to communicate with any other service by fabricating a packet with self-learned
or hard-coded destination IP address. To realize these two points, `core-network` should be able to intercept all DNS
requests and control the returned DNS reponses, for the second point `core-network` should be able to see each of the packet in a flow,
and check its validity by examing its destination address.
The first part is easily achieved, by pointing service's DNS server to `core-network` using container optons.
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


### Control Policies
##### name resolving and packet forward
##### privileged entites
##### policy configuration


### Service bootstrapping
It starts from [databox/databox-start] script. At first, network `databox-system-net` is created,
then the service `core-network` is started on this network.

The entry point of `core-network` is the main function in module [bin/core_network.ml]. In this main
function, a `monitor` is started first. It's responsible for monitoring the changes of network
interfaces of the container. If a new interface is created, or an old interface is removed, the interface
name and assigned network address are then delivered to the other component started in the same main
function after `monitor`. This component is called `junction`. `Junction` holds references to all the
network interfaces that `core-network` has. It extracts traffic from each of the interfaces, examines
them against traffic control policies, and then forward/drop them accrodingly.

Before any app/driver is installed, `core-network` has two network interfaces, one is on `databox-system-net`,
the other one is on `docker_gwbridge`, the latter is created when a swarm is started on a host or a host joins an existing swarm. `Monitor` catches both of them and passes their information to `junction` before it
starts its monitoring loop.

On network `databox-system-net`, besides `core-network`, there are also `container-manager`, `arbiter`, and
`export-service`.
