val is_dns_query : Frame.t -> bool

val is_dns_response : Frame.t -> bool

val ip_of_name : string -> Ipaddr.V4.t Lwt.t

val to_dns_response : Frame.t -> Cstruct.t -> Cstruct.t * Frame.t
(** [to_dns_resposne pkt resp] takes the original DNS query packet [pkt], and the processing result [resp]
     of the query, wraps the response in an IP packet that's ready to be passed down to lower layers in the stack.
     The second element of the returned tuple is the parsed result by {!Frame} *)

val process_dns_query :
     resolve:(string -> (Ipaddr.V4.t * Ipaddr.V4.t, Ipaddr.V4.t) result Lwt.t)
  -> Frame.t
  -> Cstruct.t Lwt.t
(** [process_dns_query ~resolve pkt] takes in an IP packet [pkt], which wraps a DNS query inside.
    The function [resolve] is used to resolve the queried domain name. Success or not, the result
    is wrapped into a DNS response packet, which is ready to be passed to lower layers down the stack. *)
