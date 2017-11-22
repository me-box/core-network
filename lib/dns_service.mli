val is_dns_query: Frame.t -> bool

val is_dns_response: Frame.t -> bool

val ip_of_name: string -> Ipaddr.V4.t Lwt.t

val to_dns_response: Frame.t -> Cstruct.t -> Cstruct.t * Frame.t

val process_dns_query: resolve:(string -> (Ipaddr.V4.t * Ipaddr.V4.t, Ipaddr.V4.t) result Lwt.t) -> Frame.t -> Cstruct.t Lwt.t
