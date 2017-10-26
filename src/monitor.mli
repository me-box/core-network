type starter = unit -> unit Lwt.t

val create : unit -> ((Intf.t * Intf.starter) Lwt_stream.t * starter) Lwt.t
