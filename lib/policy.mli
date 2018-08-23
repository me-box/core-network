type t

val create : Interfaces.t -> Nat.t -> t

val connect: t -> string -> string -> unit Lwt.t
(** [connect t name_x name_y] enables communication between service [name_x] and service [name_y]. *)

val disconnect: t -> string -> Ipaddr.V4.t -> unit Lwt.t
(** [disconnect t name ip] disables the communication between service [name] and all the others,
    [ip] is [name]'s IP address. *)

val allow_privileged_ip: t -> Ipaddr.V4.t -> unit Lwt.t

val allow_privileged_host: t -> string -> unit Lwt.t

val allow_privileged_network: t -> Ipaddr.V4.Prefix.t -> unit Lwt.t

val disallow_privileged_network: t -> Ipaddr.V4.Prefix.t -> unit Lwt.t

val is_authorized_resolve: t -> Ipaddr.V4.t -> string -> (Ipaddr.V4.t * Ipaddr.V4.t, Ipaddr.V4.t) result Lwt.t
(** [is_authorized_resolve t src_ip name] tries to decide if a query from [src_ip] for the service [name]
    is allowed, if ok, a tuple of src_ip and resolved address of [name] is returned, otherwise it's just the [src_ip]. *)

val is_authorized_transport: t -> Ipaddr.V4.t -> Ipaddr.V4.t -> bool
(** [is_authorized_transport t src_ip dst_ip] tries to decide if a packet with [src_ip] and [dst_ip] is
    allowed to be forwarded. *)

val substitute: t -> string -> Ipaddr.V4.t -> Ipaddr.V4.t -> unit Lwt.t
