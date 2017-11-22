open Lwt.Infix
open Utils.Containers
open Intf

let interfaces = Logs.Src.create "interfaces" ~doc:"Junction Policy"
module Log = (val Logs_lwt.src_log interfaces : Logs_lwt.LOG)


module IntfSet = Set.Make(struct
    type t = Intf.t
    let compare x y = Pervasives.compare x.dev y.dev
  end)


module Pkt = struct
  let notify_mtu_pkt ~src ~dst mtu jumbo_hd =
    let icmp =
      let ty = Icmpv4_wire.Destination_unreachable in
      let subheader = Icmpv4_packet.Next_hop_mtu mtu in
      let code = Icmpv4_wire.(unreachable_reason_to_int Would_fragment) in
      let icmp_t = Icmpv4_packet.({ty; subheader; code}) in
      let hd = Icmpv4_packet.Marshal.make_cstruct icmp_t ~payload:jumbo_hd in
      Cstruct.concat [hd; jumbo_hd] in

    let ip_hd =
      let buf = Cstruct.create Ipv4_wire.sizeof_ipv4 in
      let ip_t = Ipv4_packet.{
        src; dst; ttl = 38;
        proto = Marshal.protocol_to_int `ICMP; options = Cstruct.create 0} in
      let payload_len = Cstruct.len icmp in
      let result = Ipv4_packet.Marshal.into_cstruct ~payload_len ip_t buf in
      assert (result = Ok ());
      Ipv4_wire.set_ipv4_id buf (Random.int 65535);
      Ipv4_wire.set_ipv4_csum buf 0;
      let csum = Tcpip_checksum.ones_complement buf in
      Ipv4_wire.set_ipv4_csum buf csum;
      buf in

    Cstruct.concat [ip_hd; icmp]

end

type t = {
  mutable host: Intf.t option;
  mutable interfaces: IntfSet.t;
  mutable intf_cache: Intf.t IpMap.t;
}

let pp_ip = Ipaddr.V4.pp_hum

let intf_of_ip t ip =
  if IpMap.mem ip t.intf_cache then Lwt.return_ok @@ IpMap.find ip t.intf_cache else
  let found = ref None in
  IntfSet.iter (fun intf ->
      if !found <> None then ()
      else if Ipaddr.V4.Prefix.mem ip intf.network then found := Some intf
      else ()) t.interfaces;
  match !found with
  | None ->
      let msg = Format.asprintf "interface not found for %a" pp_ip ip in
      Lwt.return_error msg
  | Some intf ->
      t.intf_cache <- IpMap.add ip intf t.intf_cache;
      Lwt.return_ok intf

let intf_of_ip_exn fname t ip =
  intf_of_ip t ip >>= function
  | Ok intf -> Lwt.return intf
  | Error msg ->
      Log.warn (fun m -> m "%s: %s" fname msg) >>= fun () ->
      match t.host with
      | None -> Lwt.fail Not_found
      | Some intf -> Lwt.return intf

let to_push t dst_ip pkt =
  intf_of_ip t dst_ip >>= function
  | Ok intf ->
      intf.send_push (Some pkt);
      Lwt.return_unit
  | Error msg ->
      Log.err (fun m -> m "to_push: %s" msg)

let notify_mtu t src_ip mtu jumbo_hd = ()

let from_same_network t ipx ipy =
  intf_of_ip t ipx >>= fun intfx ->
  intf_of_ip t ipy >>= fun intfy ->
  match intfx, intfy with
  | Ok intfx, Ok intfy ->
      Lwt.return (intfx.dev = intfy.dev)
  | Error msg, _ | _, Error msg ->
      Log.err (fun m -> m "from_same_network: %s" msg) >>= fun () ->
      Lwt.return_false

let acquire_fake_dst t src_ip =
  intf_of_ip_exn "acquire_fake_dst" t src_ip >>= fun intf ->
  intf.acquire_fake_ip () >>= fun fake_ip ->
  Log.info (fun m -> m "acquire fake ip %a from %s %a" pp_ip fake_ip
            intf.Intf.dev Ipaddr.V4.Prefix.pp_hum intf.Intf.network)
  >>= fun () -> Lwt.return fake_ip

let release_fake_dst t fake_dst =
  intf_of_ip_exn  "release_fake_dst" t fake_dst >>= fun intf ->
  intf.release_fake_ip fake_dst >>= fun () ->
  Log.info (fun m -> m "release fake ip %a to %s %a" pp_ip fake_dst
            intf.Intf.dev Ipaddr.V4.Prefix.pp_hum intf.Intf.network)

let register_intf t intf dispatch_fn =
  let rec drain_pkt () =
    Lwt_stream.get intf.recv_st >>= function
    | Some buf ->
        (match Frame.parse_ipv4_pkt buf with
        | Ok Frame.(Ipv4 {src; dst; ihl} as pkt) ->
            if Cstruct.len buf > intf.mtu then
              Log.warn (fun m -> m "jumbo packet(%d) %s <- %a"
                (Cstruct.len buf) intf.Intf.dev pp_ip src) >>= fun () ->
              let jumbo_hd = Cstruct.sub buf 0 (ihl * 4 + 8) in
              let mtu_notification = Pkt.notify_mtu_pkt ~src:dst ~dst:src intf.mtu jumbo_hd in
              intf.send_push (Some mtu_notification);
              Lwt.return_unit
            else if Ipaddr.V4.is_multicast dst then
              Log.debug (fun m -> m "drop multicast packets %s <- %a" intf.Intf.dev pp_ip src)
            else dispatch_fn (buf, pkt)
        | Ok Frame.Unknown | Error _ -> Log.warn (fun m -> m "unparsable pkt from %s" intf.dev)
        | Ok (_  as pkt) -> Log.warn (fun m -> m "not ipv4 pkt: %s" (Frame.fr_info pkt)))
        >>= fun () -> drain_pkt ()
    | None -> Log.warn (fun m -> m "stream from %s closed!" intf.dev) in
  t.interfaces <- IntfSet.add intf t.interfaces;
  (match intf.Intf.gateway with
  | None -> ()
  | Some _ -> t.host <- Some intf);
  Lwt.return drain_pkt

  let deregister_intf t dev =
  let intf = ref None in
  IntfSet.iter (fun ({dev = dev'} as intf') ->
      if dev' = dev then intf := Some intf') t.interfaces;
  match !intf with
  | None -> Lwt.return_unit
  | Some intf ->
      Log.info (fun m -> m "close send stream on %s %a" intf.Intf.dev pp_ip intf.Intf.ip) >>= fun () ->
      intf.Intf.send_push None;
      t.interfaces <- IntfSet.remove intf t.interfaces;
      let cleared_cache = IpMap.filter (fun _ intf' ->
          intf'.Intf.dev <> intf.Intf.dev) t.intf_cache in
      t.intf_cache <- cleared_cache;
      Lwt.return_unit

let create () =
  let interfaces = IntfSet.empty in
  let intf_cache = IpMap.empty in
  {host = None; interfaces; intf_cache}