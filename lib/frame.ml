type t =
  | Ethernet : {src: Macaddr.t; dst: Macaddr.t; payload: t} -> t
  | Arp :
      { op: [`Request | `Reply | `Unknown]
      ; sha: Macaddr.t
      ; spa: Ipaddr.V4.t
      ; tha: Macaddr.t
      ; tpa: Ipaddr.V4.t }
      -> t
  | Ipv4 :
      { src: Ipaddr.V4.t
      ; dst: Ipaddr.V4.t
      ; dnf: bool
      ; ihl: int
      ; raw: Cstruct.t
      ; payload: t }
      -> t
  | Icmp : {raw: Cstruct.t; payload: t} -> t
  | Udp : {src: int; dst: int; len: int; raw: Cstruct.t; payload: t} -> t
  | Tcp : {src: int; dst: int; syn: bool; raw: Cstruct.t; payload: t} -> t
  | Payload : Cstruct.t -> t
  | Unknown : t

open Result

let ( >>= ) m f = match m with Ok x -> f x | Error x -> Error x

let need_space_for buf n description =
  if Cstruct.len buf < n then
    Error
      (`Msg
        (Printf.sprintf
           "buffer is too short for %s: needed %d bytes but only have %d"
           description n (Cstruct.len buf)))
  else Ok ()

let parse_ipv4_pkt_exn inner =
  need_space_for inner 16 "IP datagram"
  >>= fun () ->
  let vihl = Cstruct.get_uint8 inner 0 in
  let len = Cstruct.BE.get_uint16 inner (1 + 1) in
  let off = Cstruct.BE.get_uint16 inner (1 + 1 + 2 + 2) in
  let proto = Cstruct.get_uint8 inner (1 + 1 + 2 + 2 + 2 + 1) in
  let src =
    Cstruct.BE.get_uint32 inner (1 + 1 + 2 + 2 + 2 + 1 + 1 + 2)
    |> Ipaddr.V4.of_int32
  in
  let dst =
    Cstruct.BE.get_uint32 inner (1 + 1 + 2 + 2 + 2 + 1 + 1 + 2 + 4)
    |> Ipaddr.V4.of_int32
  in
  let dnf = (off lsr 8) land 0x40 <> 0 in
  let ihl = vihl land 0xf in
  let raw = inner in
  need_space_for inner (4 * ihl) "IP options"
  >>= fun () ->
  let inner = Cstruct.sub inner (4 * ihl) (len - (4 * ihl)) in
  ( match proto with
  | 1 ->
      need_space_for inner 8 "ICMP message"
      >>= fun () ->
      let _ty = Cstruct.get_uint8 inner 0 in
      let _code = Cstruct.get_uint8 inner 1 in
      let _csum = Cstruct.BE.get_uint16 inner 2 in
      let _id = Cstruct.BE.get_uint16 inner 4 in
      let _seq = Cstruct.BE.get_uint16 inner 6 in
      let payload = Cstruct.shift inner 8 in
      Ok (Icmp {raw= inner; payload= Payload payload})
  | 6 ->
      need_space_for inner 14 "TCP header"
      >>= fun () ->
      let src = Cstruct.BE.get_uint16 inner 0 in
      let dst = Cstruct.BE.get_uint16 inner 2 in
      let offres = Cstruct.get_uint8 inner (2 + 2 + 4 + 4) in
      let flags = Cstruct.get_uint8 inner (2 + 2 + 4 + 4 + 1) in
      need_space_for inner ((offres lsr 4) * 4) "TCP options"
      >>= fun () ->
      let payload = Cstruct.shift inner ((offres lsr 4) * 4) in
      let syn = flags land (1 lsl 1) > 0 in
      Ok (Tcp {src; dst; syn; raw= inner; payload= Payload payload})
  | 17 ->
      need_space_for inner 8 "UDP header"
      >>= fun () ->
      let src = Cstruct.BE.get_uint16 inner 0 in
      let dst = Cstruct.BE.get_uint16 inner 2 in
      let len = Cstruct.BE.get_uint16 inner 4 in
      let payload = Cstruct.shift inner 8 in
      let len = len - 8 in
      (* subtract header length *)
      Ok (Udp {src; dst; len; raw= inner; payload= Payload payload})
  | _ ->
      Error (`Msg (Printf.sprintf "unrecognized proto: %d" proto)) )
  (*Ok Unknown *)
  >>= fun payload -> Ok (Ipv4 {src; dst; dnf; ihl; raw; payload})

let parse_ipv4_pkt buf =
  try parse_ipv4_pkt_exn buf with exn -> Error (`Msg (Printexc.to_string exn))

let parse_arp_pkt inner =
  need_space_for inner 2 "ARP header"
  >>= fun () ->
  let get_ha buf offset =
    let raw = Cstruct.sub buf offset 6 in
    Macaddr.of_octets_exn @@ Cstruct.to_string raw
  in
  let code = Cstruct.BE.get_uint16 inner 6 in
  let sha = get_ha inner (6 + 2) in
  let spa = Cstruct.BE.get_uint32 inner (6 + 2 + 6) |> Ipaddr.V4.of_int32 in
  let tha = get_ha inner (6 + 2 + 6 + 4) in
  let tpa =
    Cstruct.BE.get_uint32 inner (6 + 2 + 6 + 4 + 6) |> Ipaddr.V4.of_int32
  in
  let op = match code with 1 -> `Request | 2 -> `Reply | _ -> `Unknown in
  Ok (Arp {op; sha; spa; tha; tpa})

let parse buf =
  try
    need_space_for buf 14 "ethernet frame"
    >>= fun () ->
    let ethertype = Cstruct.BE.get_uint16 buf 12 in
    let dst_option =
      Cstruct.sub buf 0 6 |> Cstruct.to_string |> Macaddr.of_octets
    in
    let src_option =
      Cstruct.sub buf 6 6 |> Cstruct.to_string |> Macaddr.of_octets
    in
    match (dst_option, src_option) with
    | None, _ ->
        Error (`Msg "failed to parse ethernet destination MAC")
    | _, None ->
        Error (`Msg "failed to parse ethernet source MAC")
    | Some dst, Some src ->
        let inner = Cstruct.shift buf 14 in
        if ethertype = 0x0800 then
          parse_ipv4_pkt inner
          >>= fun payload -> Ok (Ethernet {src; dst; payload})
        else if ethertype = 0x0806 then
          parse_arp_pkt inner
          >>= fun payload -> Ok (Ethernet {src; dst; payload})
        else Error (`Msg "Ethernet payload not ipv4 or arp pkt")
  with e ->
    Error (`Msg ("Failed to parse ethernet frame: " ^ Printexc.to_string e))

let rec fr_info = function
  | Ethernet {src; dst; _} ->
      Printf.sprintf "Ethernet %s ->%s" (Macaddr.to_string src)
        (Macaddr.to_string dst)
  | Arp {op} ->
      Printf.sprintf "Arp %s"
        ( match op with
        | `Request ->
            "request"
        | `Reply ->
            "reply"
        | `Unknown ->
            "unknown" )
  | Ipv4 {src; dst; payload} ->
      let payload_str = fr_info payload in
      Printf.sprintf "Ipv4 %s -> %s {%s}" (Ipaddr.V4.to_string src)
        (Ipaddr.V4.to_string dst) payload_str
  | Udp {src; dst; _} ->
      Printf.sprintf "Udp %d -> %d" src dst
  | Tcp {src; dst; _} ->
      Printf.sprintf "Tcp %d -> %d" src dst
  | Icmp _ ->
      "Icmp"
  | Payload _ ->
      "Payload"
  | Unknown ->
      "Unknown"
