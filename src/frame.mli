type t =
  | Ethernet: { src: Macaddr.t; dst: Macaddr.t; payload: t } -> t
  | Arp:      { op: [ `Request | `Reply | `Unknown ]; sha: Macaddr.t; spa: Ipaddr.V4.t; tha: Macaddr.t; tpa: Ipaddr.V4.t} -> t
  | Ipv4:     { src: Ipaddr.V4.t; dst: Ipaddr.V4.t; dnf: bool; ihl: int; raw: Cstruct.t; payload: t } -> t
  | Icmp:     { raw: Cstruct.t; payload: t } -> t
  | Udp:      { src: int; dst: int; len: int; raw: Cstruct.t; payload: t } -> t
  | Tcp:      { src: int; dst: int; syn: bool; raw: Cstruct.t; payload: t } -> t
  | Payload:  Cstruct.t -> t
  | Unknown:  t

val parse: Cstruct.t -> (t, [ `Msg of string]) Result.result
(** [parse buffers] parses the frame in [buffers] *)

val parse_ipv4_pkt: Cstruct.t -> (t, [ `Msg of string]) Result.result

val fr_info: t -> string
