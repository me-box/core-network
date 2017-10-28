type starter = unit -> unit Lwt.t

type intf_event = [`Up of (Intf.t * Intf.starter) | `Down of string]

val create : unit -> (intf_event Lwt_stream.t * starter) Lwt.t
