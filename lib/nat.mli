open Utils.Containers

type t

val create : unit -> t

val add_rule: t -> pair -> pair -> unit Lwt.t

val remove_rule: t -> pair -> unit Lwt.t

val get_rule_handles: t -> Ipaddr.V4.t -> pair list Lwt.t

val translate: t -> pair -> Cstruct.t * Frame.t -> (Ipaddr.V4.t * Ipaddr.V4.t * Cstruct.t * Frame.t) Lwt.t

val get_translation: t -> pair -> pair list

