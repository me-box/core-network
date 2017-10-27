type t = {
  dev : string;
  ip: Ipaddr.V4.t;
  network: Ipaddr.V4.Prefix.t;
  mtu: int;

  recv_st: Cstruct.t Lwt_stream.t;
  send_push: Cstruct.t option -> unit;

  acquire_fake_ip: unit -> Ipaddr.V4.t Lwt.t;
  release_fake_ip: Ipaddr.V4.t -> unit Lwt.t;
  fake_ips: unit -> Ipaddr.V4.t list;
}

type starter = unit -> unit Lwt.t

val create : dev:string -> cidr:string -> (t * starter) Lwt.t
