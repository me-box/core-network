type t = {
  dev : string;
  ip: Ipaddr.V4.t;
  network: Ipaddr.V4.Prefix.t;
  mtu: int;
  mutable gateway: Ipaddr.V4.t option;          (** Gateway address of the subnet {!val:t.network} *)

  recv_st: Cstruct.t Lwt_stream.t;              (** A stream of IPv4 packets *)
  send_push: Cstruct.t option -> unit;          (** To send IPv4 packets through this interface *)

  acquire_fake_ip: unit -> Ipaddr.V4.t Lwt.t;
  release_fake_ip: Ipaddr.V4.t -> unit Lwt.t;
  fake_ips: unit -> Ipaddr.V4.t list;           (** To get a list of fake IPs currently used by this interface *)
}

type starter = unit -> unit Lwt.t

val create : dev:string -> cidr:string -> (t * starter) Lwt.t
(** [create ~dev ~cidr] returns a handle on this specific interface, and a starter which could
    be used later to start sending/receiving packets from/to this interface. *)

val set_gateway: t -> Ipaddr.V4.t -> unit