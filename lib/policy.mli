type t

val create : Interfaces.t -> Nat.t -> t

val connect: t -> string -> string -> unit Lwt.t

val disconnect: t -> string -> Ipaddr.V4.t -> unit Lwt.t

val allow_privileged_ip: t -> Ipaddr.V4.t -> unit Lwt.t

val allow_privileged_host: t -> string -> unit Lwt.t

val allow_privileged_network: t -> Ipaddr.V4.Prefix.t -> unit Lwt.t

val disallow_privileged_network: t -> Ipaddr.V4.Prefix.t -> unit Lwt.t

val is_authorized_resolve: t -> Ipaddr.V4.t -> string -> (Ipaddr.V4.t * Ipaddr.V4.t, Ipaddr.V4.t) result Lwt.t

val is_authorized_transport: t -> Ipaddr.V4.t -> Ipaddr.V4.t -> bool
