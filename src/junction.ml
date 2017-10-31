open Lwt.Infix

let junction = Logs.Src.create "junction" ~doc:"Traffic junction"
module Log = (val Logs_lwt.src_log junction : Logs_lwt.LOG)

let hexdump_buf_debug desp buf =
  Log.warn (fun m ->
      let b = Buffer.create 4096 in
      Cstruct.hexdump_to_buffer b buf;
      m "%s len:%d pkt:%s" desp (Cstruct.len buf) (Buffer.contents b))

let pp_ip = Ipaddr.V4.pp_hum

module Dns_service = struct

  let dns = Logs.Src.create "dns" ~doc:"Dns service"
  module Log = (val Logs_lwt.src_log dns : Logs_lwt.LOG)

  let is_dns_query = let open Frame in function
    | Ipv4 { payload = Udp { dst = 53; _ }; _ }
    | Ipv4 { payload = Tcp { dst = 53; _ }; _ } -> true
    | _ -> false

  let query_of_pkt = let open Frame in function
    | Ipv4 { payload = Udp { dst = 53; payload = Payload buf}}
    | Ipv4 { payload = Tcp { dst = 53; payload = Payload buf}} ->
        let open Dns.Packet in
        Lwt.catch (fun () -> Lwt.return @@ parse buf) (fun e ->
            Log.err (fun m -> m "dns packet parse err!")
            >>= fun () -> Lwt.fail e)
    | _ -> Lwt.fail (Invalid_argument "Not dns query")


  let try_resolve n () =
    Lwt.catch
      (fun () ->
         let open Lwt_unix in
         (*using system resolver*)
         gethostbyname n >>= fun {h_addr_list; _} ->
         Array.to_list h_addr_list
         |> List.map (fun addr ->
             Unix.string_of_inet_addr addr
             |> Ipaddr.V4.of_string_exn)
         |> fun ips -> Lwt.return @@ `Resolved (n , List.hd ips))
      (function
      | Not_found -> Lwt.return @@ `Later n
      | e -> Lwt.fail e)


  let ip_of_name n =
    let rec keep_trying n=
      try_resolve n () >>= function
      | `Later n ->
          Log.info (fun m -> m "resolve %s later..." n) >>= fun () ->
          Lwt_unix.sleep 0.3 >>= fun () ->
          keep_trying n
      | `Resolved (n, ip) ->
          Log.info (fun m -> m "resolved: %s %a" n pp_ip ip) >>= fun () ->
          Lwt.return ip in
    Log.info (fun m -> m "try to resolve %s..." n) >>= fun () ->
    keep_trying n

  let to_dns_response pkt resp =
    let open Frame in
    match pkt with
    | Ipv4 {src = dst; dst = src; payload = Udp {src = dst_port; dst = src_port; _}; _}
    | Ipv4 {src = dst; dst = src; payload = Tcp {src = dst_port; dst = src_port; _}; _} ->
        let payload_len = Udp_wire.sizeof_udp + Cstruct.len resp in

        let ip_hd = Ipv4_packet.{options = Cstruct.create 0; src; dst; ttl = 38; proto = Marshal.protocol_to_int `UDP} in
        let ip_hd_wire = Cstruct.create Ipv4_wire.sizeof_ipv4 in
        (match Ipv4_packet.Marshal.into_cstruct ~payload_len ip_hd ip_hd_wire with
        | Error e -> raise @@ Failure "to_response_pkt -> into_cstruct"
        | Ok () ->
            Ipv4_wire.set_ipv4_id ip_hd_wire (Random.int 65535);
            Ipv4_wire.set_ipv4_csum ip_hd_wire 0;
            let cs = Tcpip_checksum.ones_complement ip_hd_wire in
            Ipv4_wire.set_ipv4_csum ip_hd_wire cs;

            let ph = Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto:`UDP payload_len in
            let udp_hd = Udp_packet.{src_port; dst_port} in
            let udp_hd_wire =  Udp_packet.Marshal.make_cstruct ~pseudoheader:ph ~payload:resp  udp_hd in

            let buf_resp = Cstruct.concat [ip_hd_wire; udp_hd_wire; resp] in
            let pkt_resp =
              match Frame.parse_ipv4_pkt buf_resp with
              | Ok fr -> fr
              | Error (`Msg msg) ->
                  Log.err (fun m -> m "dispatch -> parse_eth_payload: %s" msg) |> Lwt.ignore_result;
                  assert false
            in
            buf_resp, pkt_resp)
    | _ -> assert false


  let process_dns_query ~resolve pkt =
    let open Dns in
    query_of_pkt pkt >>= fun query ->
    begin
      let names = Packet.(List.map (fun {q_name; _} -> q_name) query.questions) in
      let name = List.hd names |> Name.to_string in
      resolve name >>= function
      | Ok (src_ip, resolved) ->
          Log.debug (fun m -> m "Dns_service: allowed %a to resolve %s" pp_ip src_ip name) >>= fun () ->
          let name = Dns.Name.of_string name in
          let rrs = Dns.Packet.[{ name; cls = RR_IN; flush = false; ttl = 0l; rdata = A resolved }] in
          Lwt.return Dns.Query.({ rcode = NoError; aa = true; answer = rrs; authority = []; additional = []})
      | Error src_ip ->
          Log.info (fun m -> m "Dns_service: banned %a to resolve %s" pp_ip src_ip name) >>= fun () ->
          Lwt.return Query.({rcode = Packet.NXDomain; aa = true; answer = []; authority = []; additional = []})
    end >>= fun answer ->
    let resp = Query.response_of_answer query answer in
    Lwt.return @@ Packet.marshal resp
end


type pair = Ipaddr.V4.t * Ipaddr.V4.t


module NAT = struct

  let nat = Logs.Src.create "NAT" ~doc:"NAT among interfaces"
  module Log = (val Logs_lwt.src_log nat : Logs_lwt.LOG)

  module PairMap = Map.Make(struct
      type t = pair
      let compare (xx, xy) (yx, yy) =
        let open Ipaddr.V4 in
        if compare xx yx = 0 && compare xy yy = 0 then 0
        else if 0 <> compare xx yx then compare xx yx
        else compare xy yy
    end)

  module IPMap = Map.Make(struct
      type t = Ipaddr.V4.t
      let compare = Ipaddr.V4.compare
    end)

  (* translation: (src_ip, dst_ip) => (nat_src_ip, nat_dst_ip) *)
  (* rule_handles: src_ip => (src_ip, dst_ip) list *)
  type  t = {
    mutable translation: pair PairMap.t;
    mutable rule_handles: pair list IPMap.t;
  }

  let get_rule_handles t ip =
    if IPMap.mem ip t.rule_handles then Lwt.return @@ IPMap.find ip t.rule_handles
    else Lwt.return_nil

  let get_translation t p =
    if PairMap.mem p t.translation then [PairMap.find p t.translation]
    else []

  let add_rule t px py =
    t.translation <- PairMap.add px py t.translation;
    let handle_key = fst px in
    let handle_value =
      if IPMap.mem handle_key t.rule_handles then
        let value = IPMap.find handle_key t.rule_handles in
        if List.mem px value then value else px :: value
      else [px] in
    t.rule_handles <- IPMap.add handle_key handle_value t.rule_handles;
    Log.info (fun m -> m "new NAT rule: (%a -> %a) => (%a -> %a)"
                 pp_ip (fst px) pp_ip (snd px) pp_ip (fst py) pp_ip (snd py))

  let remove_rule t p =
    if PairMap.mem p t.translation then
      let natted = PairMap.find p t.translation in
      t.translation <- PairMap.remove p t.translation;
      Log.info (fun m -> m "NAT rule deleted: (%a -> %a) => (%a -> %a)"
               pp_ip (fst p) pp_ip (snd p) pp_ip (fst natted) pp_ip (snd natted))
    else Lwt.return_unit >>= fun () ->

    let handle_key = fst p in
    if IPMap.mem handle_key t.rule_handles then
      let handles = IPMap.find handle_key t.rule_handles in
      if List.mem p handles then
        let handles' = List.filter (fun p' -> p' <> p) handles in
        t.rule_handles <- IPMap.add handle_key handles' t.rule_handles;
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
    let src_ip, dst_ip = PairMap.find p_orig t.translation in
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
    let translation = PairMap.empty in
    let rule_handles = IPMap.empty in
    {translation; rule_handles}
end


module IpMap = Map.Make(struct
    type t = Ipaddr.V4.t
    let compare = Ipaddr.V4.compare
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


module Interfaces = struct

  open Intf

  module IntfSet = Set.Make(struct
      type t = Intf.t
      let compare x y = Pervasives.compare x.dev y.dev
    end)

  type t = {
    mutable interfaces: IntfSet.t;
    mutable intf_cache: Intf.t IpMap.t;
  }

  let intf_of_ip_exn t ip =
    if IpMap.mem ip t.intf_cache then Lwt.return @@ IpMap.find ip t.intf_cache else
    let found = ref None in
    IntfSet.iter (fun intf ->
        if !found <> None then ()
        else if Ipaddr.V4.Prefix.mem ip intf.network then found := Some intf
        else ()) t.interfaces;
    match !found with
    | None ->
        Log.err (fun m -> m "interface not found for %a" pp_ip ip) >>= fun () ->
        Lwt.fail Not_found
    | Some intf ->
        t.intf_cache <- IpMap.add ip intf t.intf_cache;
        Lwt.return intf

  let to_push t dst_ip pkt =
    intf_of_ip_exn t dst_ip >>= fun intf ->
    intf.send_push (Some pkt);
    Lwt.return_unit

  let notify_mtu t src_ip mtu jumbo_hd = ()

  let from_same_network t ipx ipy =
    intf_of_ip_exn t ipx >>= fun intfx ->
    intf_of_ip_exn t ipy >>= fun intfy ->
    Lwt.return (intfx.dev = intfy.dev)

  let acquire_fake_dst t src_ip =
    intf_of_ip_exn t src_ip >>= fun intf ->
    intf.acquire_fake_ip () >>= fun fake_ip ->
    Log.info (fun m -> m "acquire fake ip %a from %s %a" pp_ip fake_ip
             intf.Intf.dev Ipaddr.V4.Prefix.pp_hum intf.Intf.network)
    >>= fun () -> Lwt.return fake_ip

  let release_fake_dst t fake_dst =
    intf_of_ip_exn t fake_dst >>= fun intf ->
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
    {interfaces; intf_cache}
end



module Policy = struct

  let policy = Logs.Src.create "policy" ~doc:"Junction Policy"
  module Log = (val Logs_lwt.src_log policy : Logs_lwt.LOG)

  module IPPairSet = Set.Make(struct
      type t = pair
      let compare (xx, xy) (yx, yy) =
        let open Ipaddr.V4 in
        if compare xx yx = 0 && compare xy yy = 0 then 0
        else if 0 <> compare xx yx then compare xx yx
        else compare xy yy
    end)

  module DomainPairSet = Set.Make(struct
      type t = string * string
      let compare (xx, xy) (yx, yy) =
        if (xx = yx && xy = yy) || (xx = yy && xy = yx) then 0
        else Pervasives.compare (xx, xy) (yx, yy)
    end)

  module IPSet = Set.Make(struct
      type t = Ipaddr.V4.t
      let compare = Ipaddr.V4.compare
    end)

  type t = {
    mutable pairs : DomainPairSet.t;
    mutable privileged: IPSet.t;
    mutable transport: IPPairSet.t;
    mutable resolve: (string * Ipaddr.V4.t) list IpMap.t;
    interfaces: Interfaces.t;
    nat: NAT.t;
  }


  let get_related_peers t n =
    DomainPairSet.fold (fun (nx, ny) acc ->
        if nx = n then ny :: acc
        else if ny = n then nx :: acc
        else acc) t.pairs []
    |> Lwt.return

  let add_pair t nx ny =
    t.pairs <- DomainPairSet.add (nx, ny) t.pairs;
    Lwt.return_unit

  let remove_pair t nx ny =
    t.pairs <- DomainPairSet.remove (nx, ny) t.pairs;
    Lwt.return_unit


  let get_resolve t src_ip =
    if IpMap.mem src_ip t.resolve then Lwt.return @@ IpMap.find src_ip t.resolve
    else Lwt.return_nil

  let allow_resolve t src_ip name dst_ip =
    if IpMap.mem src_ip t.resolve
    then
      let names = IpMap.find src_ip t.resolve in
      let names' = (name, dst_ip) :: (List.remove_assoc name names) in
      t.resolve <- IpMap.add src_ip names' t.resolve
    else t.resolve <- IpMap.add src_ip [name, dst_ip] t.resolve;
    Log.info (fun m -> m "allow %a to resolve %s (as %a)" pp_ip src_ip name pp_ip dst_ip)

  let forbidden_resolve t src_ip name =
    if IpMap.mem src_ip t.resolve
    then
      let names = IpMap.find src_ip t.resolve in
      let names' = List.remove_assoc name names in
      t.resolve <- IpMap.add src_ip names' t.resolve
    else ();
    Log.info (fun m -> m "forbidden %a to resolve %s" pp_ip src_ip name)


  let allow_transport t src_ip dst_ip =
    t.transport <- IPPairSet.add (src_ip, dst_ip) t.transport;
    Log.info (fun m -> m "add transport %a -> %a" pp_ip src_ip pp_ip dst_ip)
    >>= fun () -> Lwt.return_unit

  let forbidden_transport t src_ip dst_ip =
    t.transport <- IPPairSet.remove (src_ip, dst_ip) t.transport;
    Log.info (fun m -> m "removetransport %a -> %a" pp_ip src_ip pp_ip dst_ip)
    >>= fun () -> Lwt.return_unit


  let process_pair_connection t nx ny =
    if DomainPairSet.mem (nx, ny) t.pairs then Lwt.return_unit else
    Lwt_list.map_s Dns_service.ip_of_name [nx; ny] >>= fun ips ->
    let ipx = List.hd ips
    and ipy = List.hd @@ List.tl ips in
    Interfaces.from_same_network t.interfaces ipx ipy >>= function
    | false ->
        add_pair t nx ny >>= fun () ->
        (* dns request from ipx for ny should return ipy' *)
        (* dns request from ipy for nx should return ipx' *)
        Interfaces.acquire_fake_dst t.interfaces ipx >>= fun ipy' ->
        Interfaces.acquire_fake_dst t.interfaces ipy >>= fun ipx' ->
        allow_resolve t ipx ny ipy' >>= fun () ->
        allow_resolve t ipy nx ipx' >>= fun () ->
        (* NAT: ipx -> ipy' => ipx' -> ipy *)
        (* NAT: ipy -> ipx' => ipy' -> ipx *)
        allow_transport t ipx ipy' >>= fun () ->
        allow_transport t ipy ipx' >>= fun () ->
        NAT.add_rule t.nat (ipx, ipy') (ipx', ipy) >>= fun () ->
        NAT.add_rule t.nat (ipy, ipx') (ipy', ipx) >>= fun () ->
        Lwt.return_unit
    | true ->
        (* nx ny are in the same network *)
        (* DNS returns true IP directly, no NAT, no transport *)
        allow_resolve t ipx ny ipy >>= fun () ->
        allow_resolve t ipy nx ipx >>= fun () ->
        Lwt.return_unit


  let connect t nx ny =
    Lwt.async (fun () ->
        process_pair_connection t nx ny >>= fun () ->
        Log.info (fun m -> m "Policy.connect %s <> %s" nx ny));
    Lwt.return_unit

  let disconnect t n ip =
    get_resolve t ip >>= fun resolve ->
    Lwt_list.iter_p (fun (name, _) -> forbidden_resolve t ip name) resolve >>= fun () ->
    get_related_peers t n >>= fun peers ->
    Lwt_list.iter_p (fun peer -> remove_pair t n peer) peers >>= fun () ->
    NAT.get_rule_handles t.nat ip >>= fun handles ->
    Lwt_list.iter_p (fun handle ->
        let translation = NAT.get_translation t.nat handle in
        let src, dst = handle in
        forbidden_transport t src dst >>= fun () ->
        Interfaces.release_fake_dst t.interfaces dst >>= fun () ->
        NAT.remove_rule t.nat handle >>= fun () ->
        if List.length translation <> 0 then
          let dst', src' = List.hd translation in
          forbidden_transport t src' dst' >>= fun () ->
          Interfaces.release_fake_dst t.interfaces dst' >>= fun () ->
          NAT.remove_rule t.nat (src', dst')
        else Lwt.return_unit) handles >>= fun () ->
    Log.info (fun m -> m "Policy.disconnect %s" n)


  let allow_privileged t src_ip =
    t.privileged <- IPSet.add src_ip t.privileged;
    Log.info (fun m -> m "allow privileged: %a" pp_ip src_ip)


  let is_authorized_transport {transport; _} ipx ipy =
    IPPairSet.mem (ipx, ipy) transport


  let is_privileged_resolve t src_ip name =
    if IPSet.mem src_ip t.privileged then
      Dns_service.ip_of_name name >>= fun dst_ip ->
      Interfaces.from_same_network t.interfaces src_ip dst_ip >>= function
      | true ->
          allow_resolve t src_ip name dst_ip >>= fun () ->
          Lwt.return (Ok (src_ip, dst_ip))
      | false ->
          Interfaces.acquire_fake_dst t.interfaces src_ip >>= fun dst_ip' ->
          Interfaces.acquire_fake_dst t.interfaces dst_ip >>= fun src_ip' ->
          allow_resolve t src_ip name dst_ip' >>= fun () ->
          allow_transport t src_ip dst_ip' >>= fun () ->
          allow_transport t dst_ip src_ip' >>= fun () ->
          NAT.add_rule t.nat (src_ip, dst_ip') (src_ip', dst_ip) >>= fun () ->
          NAT.add_rule t.nat (dst_ip, src_ip') (dst_ip', src_ip) >>= fun () ->
          Lwt.return (Ok (src_ip, dst_ip'))
    else Lwt.return (Error src_ip)


  let is_authorized_resolve t ip name =
    if IpMap.mem ip t.resolve then
      let names = IpMap.find ip t.resolve in
      if List.mem_assoc name names then Lwt.return @@ Ok (ip, List.assoc name names)
      else is_privileged_resolve t ip name
    else is_privileged_resolve t ip name


  let create interfaces nat () =
    let pairs = DomainPairSet.empty in
    let privileged = IPSet.empty in
    let transport = IPPairSet.empty in
    let resolve = IpMap.empty in
    {pairs; privileged; transport; resolve; interfaces; nat}
end


module Local = struct

  module Backend = Basic_backend.Make
  module Service = Server.Make(Backend)

  type t = {
    id: int;
    backend: Backend.t;
    service: Service.t;
    address: Ipaddr.V4.t;
    network: Ipaddr.V4.Prefix.t;
  }

  let instance = ref None

  let is_to_local ip =
    match !instance with
    | None -> false
    | Some {address} -> 0 = Ipaddr.V4.compare ip address


  let local_virtual_mac = Macaddr.make_local (fun x -> x + 1)
  let write_to_service ethertype pkt =
    match !instance with
    | None -> Log.err (fun m -> m "Local service not initialized!")
    | Some t ->
        let open Ethif_packet in
        let source = local_virtual_mac in
        let destination = Service.mac t.service in
        let hd = {source; destination; ethertype} in
        let hd = Marshal.make_cstruct hd in
        let fr = Cstruct.append hd pkt in
        Backend.write t.backend t.id fr >>= function
        | Ok () -> Lwt.return_unit
        | Error err ->
            Log.err (fun m -> m "write_to_service err: %a" Mirage_net.pp_error err)
            >>= Lwt.return

  (*from local stack in Server*)
  let set_local_listener t interfaces =
    let open Frame in
    let listener buf =
      Lwt.catch (fun () ->
      match parse buf with
      | Ok (Ethernet {dst = dst_mac; payload = Ipv4 {dst = dst_ip}})
        when 0 = Macaddr.compare dst_mac local_virtual_mac ->
          let pkt_raw = Cstruct.shift buf Ethif_wire.sizeof_ethernet in
          Interfaces.to_push interfaces dst_ip pkt_raw
      | Ok (Ethernet {src = tha; payload = Arp {op = `Request; spa = tpa; tpa = spa}}) ->
          let arp_resp =
            let open Arpv4_packet in
            let t = {op = Arpv4_wire.Reply; sha = local_virtual_mac; spa; tha; tpa} in
            Marshal.make_cstruct t
          in
          write_to_service Ethif_wire.ARP arp_resp
      | Ok fr ->
          Log.warn (fun m -> m "not ipv4 or arp request: %s, dropped" (fr_info fr))
      | Error (`Msg msg) ->
          Log.err (fun m -> m "parse pkt from local err: %s" msg))
        (fun e -> Log.err (fun m -> m "set_local_listener: %s\n%s" (Printexc.to_string e) (Printexc.get_backtrace ()))
        >>= fun () -> Lwt.fail e)
    in
    Backend.set_listen_fn t.backend t.id listener


  let create intf interfaces =
    let yield = Lwt_main.yield in
    let use_async_readers = true in
    let backend = Backend.create ~yield ~use_async_readers () in
    let id =
      match Backend.register backend with
      | `Ok id -> id
      | `Error err ->
          Log.err (fun m -> m "Backend.register err: %a" Mirage_net.pp_error err)
          |> Lwt.ignore_result; -1
    in
    let address = intf.Intf.ip in
    let network = intf.Intf.network in
    Service.make backend address >>= fun service ->
    let t = {id; backend; service; network; address} in
    set_local_listener t interfaces;
    instance := Some t;
    Lwt.return t


  open Service

  let connect_for po =
    let connect_handler = fun req ->
      Lwt.catch (fun () ->
          json_of_body_exn req >>= fun obj ->
          try
            let open Ezjsonm in
            let dict = get_dict (value obj) in
            let name = List.assoc "name" dict |> get_string in
            let peers = List.assoc "peers" dict |> get_list get_string in
            Lwt_list.map_p (fun peer -> Policy.connect po name peer) peers >>= fun _ ->
            let status = Cohttp.Code.(`OK) in
            Lwt.return (status, `Json (`O []))
          with e -> Lwt.fail e) (fun e ->
          let msg = Printf.sprintf "/connect server err: %s" (Printexc.to_string e) in
          let status = Cohttp.Code.(`Code 500) in
          Lwt.return (status, `String msg)) >>= fun (code, body) ->
      respond' ~code body
    in
    post "/connect" connect_handler

  let disconnect_for po =
    let disconnect_handler = fun req ->
      Lwt.catch (fun () ->
          json_of_body_exn req >>= fun obj ->
          try
            let open Ezjsonm in
            let dict = get_dict (value obj) in
            let name = List.assoc "name" dict |> get_string in
            let ip   =
              List.assoc "ip" dict
              |> get_string
              |> Ipaddr.V4.Prefix.of_address_string_exn
              |> snd in
            Policy.disconnect po name ip >>= fun () ->
            let status = Cohttp.Code.(`OK) in
            Lwt.return (status, `Json (`O []))
          with e -> Lwt.fail e) (fun e ->
          let msg = Printf.sprintf "/disconnect server err: %s" (Printexc.to_string e) in
          let status = Cohttp.Code.(`Code 500) in
          Lwt.return (status, `String msg)) >>= fun (code, body) ->
      respond' ~code body
    in
    post "/disconnect" disconnect_handler

  let add_privileged po =
    let add_privileged_handler = fun req ->
      Lwt.catch (fun () ->
          json_of_body_exn req >>= fun obj ->
          try
            let open Ezjsonm in
            let dict = get_dict (value obj) in
            let src_ip_str = List.assoc "src_ip" dict |> get_string in
            let src_ip = Ipaddr.V4.of_string_exn src_ip_str in
            Policy.allow_privileged po src_ip >>= fun () ->
            Lwt.return (`OK, `Json (`O []))
          with e -> Lwt.fail e) (fun e ->
          let msg = Printf.sprintf "/privileged server err: %s" (Printexc.to_string e) in
          Lwt.return (`Code 500, `String msg)) >>= fun (code, body) ->
      respond' ~code body
    in
    post "/privileged" add_privileged_handler

  let start_service t po =
   let callback = callback_of_routes [
        connect_for po;
        disconnect_for po;
        add_privileged po;
      ] in
    start t.service ~callback


  let initialize intf policy interfaces =
    create intf interfaces >>= fun t ->
    Lwt.return @@ start_service t policy
end


module Dispatcher = struct

  type t = {
    interfaces: Interfaces.t;
    policy: Policy.t;
    nat: NAT.t;
  }

  let dispatch t (buf, pkt) =
    let src_ip, dst_ip, ihl = let open Frame in match pkt with
      | Ipv4 {src; dst; ihl; _} -> src, dst, ihl
      | _ ->
          Log.err (fun m -> m "Dispathcer: dispatch %s" (Frame.fr_info pkt)) |> Lwt.ignore_result;
          assert false in
    if Dns_service.is_dns_query pkt then
      Log.debug (fun m -> m "Dispatcher: a dns query from %a" pp_ip src_ip) >>= fun () ->
      let resolve = Policy.is_authorized_resolve t.policy src_ip in
      Dns_service.process_dns_query ~resolve pkt >>= fun resp ->
      let resp = Dns_service.to_dns_response pkt resp in
      Interfaces.to_push t.interfaces dst_ip (fst resp)
    else if Local.is_to_local dst_ip then
      Local.write_to_service Ethif_wire.IPv4 buf
    else if Policy.is_authorized_transport t.policy src_ip dst_ip then
      NAT.translate t.nat (src_ip, dst_ip) (buf, pkt) >>= fun (nat_src_ip, nat_dst_ip, nat_buf, nat_pkt) ->
      Log.debug (fun m -> m "Dispatcher: allowed pkt[NAT] %a -> %a => %a -> %a"
          pp_ip src_ip pp_ip dst_ip pp_ip nat_src_ip pp_ip nat_dst_ip) >>= fun () ->
      Interfaces.to_push t.interfaces nat_dst_ip nat_buf
    else Log.warn (fun m -> m "Dispatcher: dropped pkt %a -> %a" pp_ip src_ip pp_ip dst_ip)


  let create interfaces nat policy =
    {interfaces; policy; nat}
end


let create intf_st =
  let interfaces = Interfaces.create () in
  let nat = NAT.create () in
  let policy = Policy.create interfaces nat () in
  let dispatcher = Dispatcher.create interfaces nat policy in
  let dispatch_fn = Dispatcher.dispatch dispatcher in

  let register_and_start intf intf_starter =
    Interfaces.register_intf interfaces intf dispatch_fn >>= fun interfaces_starter ->
    let t = fun () ->
      Lwt.finalize (fun () ->
          Lwt.catch (fun () ->
            Log.info (fun m -> m "register intf %s %a %a" intf.Intf.dev
              pp_ip intf.Intf.ip Ipaddr.V4.Prefix.pp_hum intf.Intf.network) >>= fun () ->
            Lwt.join [intf_starter (); interfaces_starter ()])
            (fun exn -> Log.err (fun m -> m "intf %s err: %s" intf.Intf.dev (Printexc.to_string exn))))
        (fun () -> Log.info (fun m -> m "intf %s exited!" intf.Intf.dev)) in
    Lwt.return @@ Lwt.async t in

  Lwt_stream.next intf_st >>= (function
  | `Down dev -> Lwt.fail (Invalid_argument dev)
  | `Up (local, local_starter) -> Lwt.return (local, local_starter))
  >>= fun (local, local_starter) ->
  Local.initialize local policy interfaces >>= fun service_starter ->
  register_and_start local local_starter >>= fun () ->
  Log.info (fun m -> m "start local service...") >>= fun () ->
  Lwt.return @@ Lwt.async service_starter >>= fun () ->

  let rec junction_lp () =
    Lwt_stream.get intf_st >>= function
    | None -> Log.warn (fun m -> m "monitor stream closed!" )
    | Some (`Up (intf, intf_starter)) ->
        register_and_start intf intf_starter >>= fun () ->
        junction_lp ()
    | Some (`Down dev) ->
        Interfaces.deregister_intf interfaces dev >>= fun () ->
        junction_lp ()
    in
  Lwt.return junction_lp
