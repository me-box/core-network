type t

val create : unit -> t

val register_intf :
     t
  -> Intf.t
  -> (Cstruct.t * Frame.t -> unit Lwt.t)
  -> (unit -> unit Lwt.t) Lwt.t
(** [register_intf t intf dispatch_fn] puts the interface [intf] under the management of [t], which
    includes feeding packets received from [intf] into the consumer function [dispatch_fn],
    [dispatch_fn] each time consumes a tuple of well-formatted IPv4 packet and its parsed result by {!Frame},
    the returned initiator is used to start the feeding. *)

val deregister_intf : t -> string -> unit Lwt.t
(** [deregister_intf t dev] deregisters an interface by its {!recfield:Intf.t.dev} *)

val acquire_fake_dst : t -> Ipaddr.V4.t -> Ipaddr.V4.t Lwt.t
(** [acquire_fake_dst t ip] returns a fake address from the same subnet as [ip]. *)

val release_fake_dst : t -> Ipaddr.V4.t -> unit Lwt.t

val from_same_network : t -> Ipaddr.V4.t -> Ipaddr.V4.t -> bool Lwt.t

val to_push : t -> Ipaddr.V4.t -> Cstruct.t -> unit Lwt.t
(** [to_push t dst_ip pkt] finds the right interface {Intf.t} to send the IPv4
    packet [pkt] based on its destination address [dst_ip] and sends it. *)

val substitute : t -> Ipaddr.V4.t -> Ipaddr.V4.t -> unit Lwt.t
(** [substitute t old_ip new_ip], internally [t] maintains a cache to look up
    the interface {Intf.t} to send a packet by its destination IP address, this is
    to substitue any [old_ip] found in the cache for [new_ip], called when there is a
    service restart happening. *)

val relay_bcast : t -> Cstruct.t -> unit
