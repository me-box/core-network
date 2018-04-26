type t

val create: unit -> t

val register_intf: t -> Intf.t -> (Cstruct.t * Frame.t -> unit Lwt.t) -> (unit -> unit Lwt.t) Lwt.t

val deregister_intf: t -> string -> unit Lwt.t


val acquire_fake_dst: t -> Ipaddr.V4.t -> Ipaddr.V4.t Lwt.t

val release_fake_dst: t -> Ipaddr.V4.t -> unit Lwt.t

val from_same_network: t -> Ipaddr.V4.t -> Ipaddr.V4.t -> bool Lwt.t


val to_push: t -> Ipaddr.V4.t -> Cstruct.t -> unit Lwt.t

val substitute: t -> Ipaddr.V4.t -> Ipaddr.V4.t -> unit Lwt.t

val relay_bcast: t -> Cstruct.t -> unit
