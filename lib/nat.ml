open Lwt.Infix
open Utils.Containers

let nat = Logs.Src.create "NAT" ~doc:"NAT among interfaces"
module Log = (val Logs_lwt.src_log nat : Logs_lwt.LOG)


(* translation: (src_ip, dst_ip) => (nat_src_ip, nat_dst_ip) *)
(* rule_handles: src_ip => (src_ip, dst_ip) list *)
type  t = {
  mutable translation: pair IpPairMap.t;
  mutable rule_handles: pair list IpMap.t;
}

let pp_ip = Ipaddr.V4.pp_hum

let get_rule_handles t ip =
  if IpMap.mem ip t.rule_handles then Lwt.return @@ IpMap.find ip t.rule_handles
  else Lwt.return_nil

let get_translation t p =
  if IpPairMap.mem p t.translation then [IpPairMap.find p t.translation]
  else []

let add_rule t px py =
  t.translation <- IpPairMap.add px py t.translation;
  let handle_key = fst px in
  let handle_value =
    if IpMap.mem handle_key t.rule_handles then
      let value = IpMap.find handle_key t.rule_handles in
      if List.mem px value then value else px :: value
    else [px] in
  t.rule_handles <- IpMap.add handle_key handle_value t.rule_handles;
  Log.info (fun m -> m "new NAT rule: (%a -> %a) => (%a -> %a)"
               pp_ip (fst px) pp_ip (snd px) pp_ip (fst py) pp_ip (snd py))

let remove_rule t p =
  if IpPairMap.mem p t.translation then
    let natted = IpPairMap.find p t.translation in
    t.translation <- IpPairMap.remove p t.translation;
    Log.info (fun m -> m "NAT rule deleted: (%a -> %a) => (%a -> %a)"
             pp_ip (fst p) pp_ip (snd p) pp_ip (fst natted) pp_ip (snd natted))
  else Lwt.return_unit >>= fun () ->

  let handle_key = fst p in
  if IpMap.mem handle_key t.rule_handles then
    let handles = IpMap.find handle_key t.rule_handles in
    if List.mem p handles then
      let handles' = List.filter (fun p' -> p' <> p) handles in
      t.rule_handles <- IpMap.add handle_key handles' t.rule_handles;
      Lwt.return_unit
    else Lwt.return_unit
  else Lwt.return_unit


let set_ipv4_checksum buf ihl =
  let hd = Cstruct.sub buf 0 (4 * ihl) in
  Ipv4_wire.set_ipv4_csum buf 0;
  let csum = Tcpip_checksum.ones_complement hd in
  Ipv4_wire.set_ipv4_csum buf csum

let set_udp_checksum buf ph =
  Udp_wire.set_udp_checksum buf 0;
  let csum = Tcpip_checksum.ones_complement_list [ph; buf] in
  Udp_wire.set_udp_checksum buf csum

let set_tcp_checksum buf ph =
  Tcp.Tcp_wire.set_tcp_checksum buf 0;
  let csum = Tcpip_checksum.ones_complement_list [ph; buf] in
  Tcp.Tcp_wire.set_tcp_checksum buf csum

let translate t p_orig (buf, pkt) =
  (* pkt actually doesn't matter as not transmitted *)
  let open Frame in
  let src_ip, dst_ip = IpPairMap.find p_orig t.translation in
  let not_expected log =
    Log.err (fun m -> m "%s not expected value in match" log) >>= fun () ->
    Lwt.fail (Invalid_argument log) in
  match pkt with
  | Ipv4 {ihl; raw = nat_buf; payload} ->
      Ipv4_wire.set_ipv4_src nat_buf (Ipaddr.V4.to_int32 src_ip);
      Ipv4_wire.set_ipv4_dst nat_buf (Ipaddr.V4.to_int32 dst_ip);
      set_ipv4_checksum nat_buf ihl;
      (match payload with
      | Udp {len; raw = udp_buf} ->
          let ph = Ipv4_packet.Marshal.pseudoheader ~src:src_ip ~dst:dst_ip ~proto:`UDP len in
          set_udp_checksum udp_buf ph
      | Tcp {raw = tcp_buf} ->
          let len = Cstruct.len tcp_buf in
          let ph = Ipv4_packet.Marshal.pseudoheader ~src:src_ip ~dst:dst_ip ~proto:`TCP len in
          set_tcp_checksum tcp_buf ph
      | Icmp _ -> ()
      | _ -> Lwt.ignore_result @@ not_expected "ipv4_payload");
      Lwt.return (src_ip, dst_ip, nat_buf, pkt)
  | _ -> not_expected "translate_operand"


let create () =
  let translation = IpPairMap.empty in
  let rule_handles = IpMap.empty in
  {translation; rule_handles}
