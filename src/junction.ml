open Lwt.Infix

let bridge = Logs.Src.create "bridge" ~doc:"Bridge"
module Log = (val Logs_lwt.src_log bridge : Logs_lwt.LOG)

let hexdump_buf_debug desp buf =
  Log.warn (fun m ->
      let b = Buffer.create 4096 in
      Cstruct.hexdump_to_buffer b buf;
      m "%s len:%d pkt:%s" desp (Cstruct.len buf) (Buffer.contents b))

let pp_ip = Ipaddr.V4.pp_hum

module Dns_service = struct

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


  let rec try_resolve n () =
    Lwt.catch
      (fun () ->
         let open Lwt_unix in
         (*using system resolver*)
         gethostbyname n >>= fun {h_addr_list; _} ->
         Array.to_list h_addr_list
         |> List.map (fun addr ->
             Unix.string_of_inet_addr addr
             |> Ipaddr.V4.of_string_exn)
         |> fun ips -> Lwt.return @@ `Resolved (List.hd ips))
      (function
      | Not_found -> Lwt.return @@ `Later (n, try_resolve n)
      | e -> Lwt.fail e)


  let ip_of_name ?(sleep_time = 2.) n =
    try_resolve n () >>= fun maybe_ip ->
    let rec keep_trying = function
    | `Later (n, to_resolve) ->
        Log.debug (fun m -> m "to resolve %s after %fs" n sleep_time) >>= fun () ->
        Lwt_unix.sleep sleep_time >>= fun () ->
        to_resolve () >>= keep_trying
    | `Resolved ip ->
        Log.info (fun m -> m "resolved: %s %a" n pp_ip ip) >>= fun () ->
        Lwt.return ip in
    Log.info (fun m -> m "trying to resolve %s..." n) >>= fun () ->
    keep_trying maybe_ip


  let to_dns_response t pkt resp =
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

  module PairMap = Map.Make(struct
      type t = pair
      let compare (xx, xy) (yx, yy) =
        let open Ipaddr.V4 in
        if compare xx yx = 0 && compare xy yy = 0 then 0
        else compare xx yy
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


module Endpoints = struct

  module EndpMap = Map.Make(struct
      type t = Proto.endpoint
      let compare x y = Pervasives.compare x.Proto.interface y.Proto.interface
    end)

  module EndpSet = Set.Make(struct
      type t = Proto.endpoint
      let compare x y = Pervasives.compare x.Proto.interface y.Proto.interface
    end)

  module ReqMap = Map.Make(struct type t = int32 let compare = Pervasives.compare end)

  type t = {
    mutable endp_set: EndpSet.t;
    mutable connections: Proto.Server.client_connection EndpMap.t;
    mutable push_fn: ((Cstruct.t * Frame.t) option -> unit) EndpMap.t;
    mutable push_cache: Proto.endpoint IpMap.t;
    mutable req_queue: ((Ipaddr.V4.t, unit) result Lwt.u) ReqMap.t;
    mutex: Lwt_mutex.t;
  }

  let endp_of_ip t dst =
    Lwt_mutex.with_lock t.mutex (fun () ->
        (if IpMap.mem dst t.push_cache then Some (IpMap.find dst t.push_cache) else
         EndpSet.fold (fun endp acc ->
             match acc with
             | Some _ -> acc
             | None ->
                 let network = Ipaddr.V4.Prefix.make endp.netmask endp.ip_addr in
                 if not @@ Ipaddr.V4.Prefix.mem dst network then acc else
                 let push_cache = IpMap.add dst endp t.push_cache in
                 t.push_cache <- push_cache;
                 Some endp) t.endp_set None)
        |> Lwt.return)


  let from_same_network t ipx ipy =
    endp_of_ip t ipx >>= fun endpx ->
    endp_of_ip t ipy >>= fun endpy ->
    match endpx, endpy with
    | Some endpx, Some endpy ->
        Lwt.return (endpx.Proto.interface = endpy.Proto.interface)
    | _ ->
        Lwt.return false

  let to_push t dst dg =
    endp_of_ip t dst >>= function
    | None ->
        Log.warn (fun m -> m "no endp to push for %a, drop" pp_ip dst)
        >>= Lwt_result.return
    | Some endp ->
        if endp.Proto.mtu >= Cstruct.len @@ fst dg then
          let push_fn = EndpMap.find endp t.push_fn in
          push_fn (Some dg);
          Lwt_result.return ()
        else Lwt_result.fail (`MTU endp.Proto.mtu)


  let notify_mtu t dst mtu hd' =
    let ty = Icmpv4_wire.Destination_unreachable in
    let subheader = Icmpv4_packet.Next_hop_mtu mtu in
    let code = Icmpv4_wire.(unreachable_reason_to_int Would_fragment) in
    let icmp_t = Icmpv4_packet.({ty; subheader; code}) in
    let hd = Icmpv4_packet.Marshal.make_cstruct icmp_t ~payload:hd' in
    let icmp = Cstruct.concat [hd; hd'] in

    endp_of_ip t dst >>= function
    | None -> Log.warn (fun m -> m "no endp to send next hop notification!")
    | Some {ip_addr = src} ->
        let ip_hd = Ipv4_packet.{
            src; dst; ttl = 38;
            proto = Marshal.protocol_to_int `ICMP; options = Cstruct.create 0} in
        let ip_hd_wire = Cstruct.create Ipv4_wire.sizeof_ipv4 in
        let payload_len = Cstruct.len icmp in
        let result = Ipv4_packet.Marshal.into_cstruct ~payload_len ip_hd ip_hd_wire in
        assert (result = Ok ());
        Ipv4_wire.set_ipv4_id   ip_hd_wire (Random.int 65535);
        Ipv4_wire.set_ipv4_csum ip_hd_wire 0;
        let csum = Tcpip_checksum.ones_complement ip_hd_wire in
        Ipv4_wire.set_ipv4_csum ip_hd_wire csum;

        let buf = Cstruct.concat [ip_hd_wire; icmp] in
        match Frame.parse_ipv4_pkt buf with
        | Ok pkt ->
            Log.info (fun m -> m "notify %a of MTU %d" pp_ip dst mtu) >>= fun () ->
            to_push t dst (buf, pkt) >>= fun _ ->
            Lwt.return_unit
        | Error _ ->
            Log.err (fun m -> m "notify_mtu: fail to parse fabricated ICMP packet")


  let rec comm_monitor t conn =
    let open Proto in
    Proto.Server.recv_comm conn >>= function
    | ACK (ip, id) ->
        Log.info (fun m -> m "ACK %a %ld" pp_ip ip id) >>= fun () ->
        Lwt_mutex.with_lock t.mutex (fun () ->
            let wakener = ReqMap.find id t.req_queue in
            Lwt.wakeup wakener (Ok ip);
            t.req_queue <- ReqMap.remove id t.req_queue;
            Lwt.return_unit) >>= fun () ->
        comm_monitor t conn
    | IP_DUP dup ->
        Log.warn (fun m -> m "DUPLICATE: %a!" pp_ip dup) >>= fun () ->
        comm_monitor t conn
    | IP_REQ _ | IP_RTN _ ->
        Log.err (fun m -> m "IP_REQ|IP_RTN from client?!") >>= fun () ->
        comm_monitor t conn

  let enqueue_req t id u =
    Lwt_mutex.with_lock t.mutex (fun () ->
        t.req_queue <- ReqMap.add id u t.req_queue;
        Lwt.return_unit)

  let dequeue_req t id =
    Lwt_mutex.with_lock t.mutex (fun () ->
        t.req_queue <- ReqMap.remove id t.req_queue;
        Lwt.return_unit)

  let _req_id = ref 0l
  let req_id () =
    let id = !_req_id in
    _req_id := Int32.succ id;
    id

  let rec claim_fake_dst t ip =
    let fake, u = Lwt.wait () in
    let time_out () = Lwt_unix.sleep 1.0 >>= fun () -> Lwt.return @@ Error () in
    endp_of_ip t ip >>= function
    | None ->
        Log.err (fun m -> m "no endp to fake dst for %a" pp_ip ip) >>= fun () ->
        Lwt.fail_with "claim_fake_dst"
    | Some endp ->
        let id = req_id () in
        let comm = Proto.IP_REQ id in
        let conn = EndpMap.find endp t.connections in
        Log.debug (fun m -> m "IP_REQ %ld on %s(%a) for %a" id endp.interface pp_ip endp.ip_addr pp_ip ip) >>= fun () ->
        enqueue_req t id u >>= fun () ->
        Proto.Server.send_comm conn comm >>= fun () ->
        Lwt.pick [fake; time_out ()] >>= function
        | Ok ip -> Lwt.return ip
        | Error () ->
            Log.warn (fun m -> m "claim_fake_ip time out! retry...") >>= fun () ->
            dequeue_req t id >>= fun () ->
            claim_fake_dst t ip

  let forfeit_fake_dst t ip =
    endp_of_ip t ip >>= function
    | None ->
        Log.warn (fun m -> m "endp for %a destroied already?" pp_ip ip)
    | Some endp ->
        let comm = Proto.IP_RTN ip in
        let conn = EndpMap.find endp t.connections in
        Proto.Server.send_comm conn comm


  let register_endpoint t endp conn push =
    Lwt.async (fun () -> Lwt.catch (fun () -> comm_monitor t conn) (function
      | Lwt_stream.Empty -> Lwt.return_unit
      | exn -> Lwt.fail exn));
    Lwt_mutex.with_lock t.mutex (fun () ->
        if not @@ EndpSet.mem endp t.endp_set then
          let endp_set = EndpSet.add endp t.endp_set in
          let connections = EndpMap.add endp conn t.connections in
          let push_fn = EndpMap.add endp push t.push_fn in
          t.endp_set <- endp_set;
          t.connections <- connections;
          t.push_fn <- push_fn;
          Lwt.return_unit
        else Lwt.return_unit)

  let cancel_endpoint t endp =
    Lwt_mutex.with_lock t.mutex (fun () ->
        t.endp_set <- EndpSet.remove endp t.endp_set;
        t.connections <- EndpMap.remove endp t.connections;
        t.push_fn <- EndpMap.remove endp t.push_fn;
        Lwt.return_unit)

  let create () : t =
    let endp_set = EndpSet.empty in
    let connections = EndpMap.empty in
    let push_fn = EndpMap.empty in
    let push_cache = IpMap.empty in
    let req_queue = ReqMap.empty in
    let mutex = Lwt_mutex.create () in
    {endp_set; connections; push_fn; push_cache; req_queue; mutex}
end



module Policy = struct

  module IPPairSet = Set.Make(struct
      type t = pair
      let compare (xx, xy) (yx, yy) =
        let open Ipaddr.V4 in
        if compare xx yx = 0 && compare xy yy = 0 then 0
        else compare xx yy
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
    endpoints: Endpoints.t;
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
    Lwt.return_unit

  let forbidden_transport t src_ip dst_ip =
    t.transport <- IPPairSet.remove (src_ip, dst_ip) t.transport;
    Lwt.return_unit


  let process_pair_connection t nx ny =
    if DomainPairSet.mem (nx, ny) t.pairs then Lwt.return_unit else
    Lwt_list.map_s Dns_service.ip_of_name [nx; ny] >>= fun ips ->
    let ipx = List.hd ips
    and ipy = List.hd @@ List.tl ips in
    Endpoints.from_same_network t.endpoints ipx ipy >>= function
    | false ->
        add_pair t nx ny >>= fun () ->
        (* dns request from ipx for ny should return ipy' *)
        (* dns request from ipy for nx should return ipx' *)
        Endpoints.claim_fake_dst t.endpoints ipx >>= fun ipy' ->
        Endpoints.claim_fake_dst t.endpoints ipy >>= fun ipx' ->
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
        Endpoints.forfeit_fake_dst t.endpoints dst >>= fun () ->
        NAT.remove_rule t.nat handle >>= fun () ->
        if List.length translation <> 0 then
          let dst', src' = List.hd translation in
          forbidden_transport t src' dst' >>= fun () ->
          Endpoints.forfeit_fake_dst t.endpoints dst' >>= fun () ->
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
      Endpoints.from_same_network t.endpoints src_ip dst_ip >>= function
      | true ->
          allow_resolve t src_ip name dst_ip >>= fun () ->
          Lwt.return (Ok (src_ip, dst_ip))
      | false ->
          Endpoints.claim_fake_dst t.endpoints src_ip >>= fun dst_ip' ->
          Endpoints.claim_fake_dst t.endpoints dst_ip >>= fun src_ip' ->
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


  let create endpoints nat () =
    let pairs = DomainPairSet.empty in
    let privileged = IPSet.empty in
    let transport = IPPairSet.empty in
    let resolve = IpMap.empty in
    {pairs; privileged; transport; resolve; endpoints; nat}
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

  let lock = Lwt_mutex.create ()
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
  let set_local_listener t endpoints =
    let open Frame in
    let listener buf =
      Lwt.catch (fun () ->
      match parse buf with
      | Ok (Ethernet {dst = dst_mac; payload = (Ipv4 {dst = dst_ip} as pkt)})
        when 0 = Macaddr.compare dst_mac local_virtual_mac ->
          let pkt_raw = Cstruct.shift buf Ethif_wire.sizeof_ethernet in
          Endpoints.to_push endpoints dst_ip (pkt_raw, pkt) >>= (function
          | Ok () | Error _ -> Lwt.return_unit)
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


  let create endp endpoints =
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
    let address = endp.Proto.ip_addr in
    let network = Ipaddr.V4.Prefix.make endp.Proto.netmask address in
    Service.make backend address >>= fun service ->
    let t = {id; backend; service; network; address} in
    set_local_listener t endpoints;
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


  let initialize_if_not endp policy endpoints =
    Lwt_mutex.with_lock lock (fun () ->
        match !instance with
        | None ->
            create endp endpoints >>= fun t ->
            start_service t policy ()
        | Some _ -> Lwt.return_unit)
end


module Dispatcher = struct

  type t = {
    endpoints: Endpoints.t;
    policy: Policy.t;
    nat: NAT.t;
  }

  let dispatch t endp (buf, pkt) =
    let src_ip, dst_ip, ihl = let open Frame in match pkt with
      | Ipv4 {src; dst; ihl; _} -> src, dst, ihl
      | _ ->
          Log.err (fun m -> m "Dispathcer: dispatch %s" (Frame.fr_info pkt)) |> Lwt.ignore_result;
          assert false in
    if Dns_service.is_dns_query pkt then
      Log.debug (fun m -> m "Dispatcher: a dns query from %a" pp_ip src_ip) >>= fun () ->
      let resolve = Policy.is_authorized_resolve t.policy src_ip in
      Dns_service.process_dns_query ~resolve pkt >>= fun resp ->
      let resp = Dns_service.to_dns_response t pkt resp in
      Endpoints.to_push t.endpoints dst_ip resp >>= fun _ ->
      Lwt.return_unit
    else if Local.is_to_local dst_ip then
      Log.debug (fun m -> m "Dispatcher: allowed pkt[local] %a -> %a" pp_ip src_ip pp_ip dst_ip) >>= fun () ->
      Local.write_to_service Ethif_wire.IPv4 buf
    else if Policy.is_authorized_transport t.policy src_ip dst_ip then
      Log.debug (fun m -> m "Dispatcher: allowed pkt %a -> %a" pp_ip src_ip pp_ip dst_ip) >>= fun () ->
      NAT.translate t.nat (src_ip, dst_ip) (buf, pkt) >>= fun (nat_src_ip, nat_dst_ip, nat_buf, nat_pkt) ->
      Log.debug (fun m -> m "Dispatcher: after NAT %a -> %a" pp_ip nat_src_ip pp_ip nat_dst_ip) >>= fun () ->
      Endpoints.to_push t.endpoints nat_dst_ip (nat_buf, nat_pkt) >>= (function
        | Ok () -> Lwt.return_unit
        | Error (`MTU mtu) ->
            Log.info (fun m -> m "from endpoint %s: %s (len:%d)" endp.Proto.interface (Frame.fr_info pkt) (Cstruct.len buf)) >>= fun () ->
            let jumbo_hd = Cstruct.sub buf 0 (ihl * 4 + 8) in
            Endpoints.notify_mtu t.endpoints src_ip mtu jumbo_hd)
    else Log.warn (fun m -> m "Dispatcher: dropped pkt %a -> %a" pp_ip src_ip pp_ip dst_ip)


  let create endpoints nat policy =
    {endpoints; policy; nat}
end


let rec from_endpoint endp conn push_in =
  Lwt.catch (fun () ->
      Proto.Server.recv_pkt conn >>= fun buf ->
      (*hexdump_buf_debug "from_endpoint" buf >>= fun () ->*)
      Frame.parse_ipv4_pkt buf |> function
      | Ok fr ->
          Log.debug (fun m -> m "from endpoint %s: %s (len:%d)" endp.Proto.interface (Frame.fr_info fr) (Cstruct.len buf)) >>= fun () ->
          push_in @@ Some (buf, fr);
          from_endpoint endp conn push_in
      | Error (`Msg msg) ->
          Log.warn (fun m -> m "%s err parsing incoming pkt %s: DROP" endp.Proto.interface msg) >>= fun () ->
          from_endpoint endp conn push_in
    ) (function
    | Lwt_stream.Empty -> Lwt.return_unit
    | exn -> Lwt.fail exn)


let rec to_endpoint endp conn out_s =
  Lwt_stream.get out_s >>= function
  | None ->
      Log.warn (fun m -> m "output stream closed ?!")
  | Some (buf, _) ->
      match Frame.parse_ipv4_pkt buf with
      | Ok pkt ->
          (*hexdump_buf_debug "to_endpoint" buf >>= fun () ->*)
          Log.debug (fun m -> m "to endpoint %s: %s (len:%d)" endp.Proto.interface (Frame.fr_info pkt) (Cstruct.len buf)) >>= fun () ->
          Proto.Server.send_pkt conn buf >>= fun () ->
          to_endpoint endp conn out_s
      | Error (`Msg msg) -> Log.warn (fun m -> m "to endpoint %s: %s (len: %d)" endp.Proto.interface msg (Cstruct.len buf))


let async_exception () =
  let hook = !Lwt.async_exception_hook in
  let hook' = fun exn ->
    Log.err (fun m -> m "aysnc exception: %s\n%s" (Printexc.to_string exn) (Printexc.get_backtrace ()))
    |> Lwt.ignore_result;
    hook exn
  in
  Lwt.async_exception_hook := hook'


let main path logs =
  Utils.set_up_logs logs >>= fun () ->
  Proto.Server.bind path >>= fun server ->

  let endpoints = Endpoints.create () in
  let nat = NAT.create () in
  let policy = Policy.create endpoints nat () in
  let disp = Dispatcher.create endpoints nat policy in
  let serve_endp endp conn =
    let () = Lwt.async (fun () -> Local.initialize_if_not endp policy endpoints) in
    let in_s, push_in = Lwt_stream.create () in
    let out_s, push_out = Lwt_stream.create () in
    Log.info (fun m -> m "client %s made connection!" @@ Proto.endp_to_string endp) >>= fun () ->

    Endpoints.register_endpoint endpoints endp conn push_out >>= fun () ->
    let rec dispatch endp in_s =
      Lwt_stream.get in_s >>= function
      | Some (buf, pkt) ->
          Dispatcher.dispatch disp endp (buf, pkt) >>= fun () ->
          dispatch endp in_s
      | None ->
          Log.warn (fun m -> m "endpoint %s closed?!" @@ Proto.endp_to_string endp)
    in
    Lwt.pick [
      dispatch endp in_s;
      from_endpoint endp conn push_in;
      to_endpoint endp conn out_s
    ] >>= fun () ->
    Endpoints.cancel_endpoint endpoints endp
  in

  Proto.Server.listen server serve_endp >>= fun () ->
  Monitor.create () >>= fun _ -> Lwt.return_unit


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
    intf.send_push pkt;
    Lwt.return_unit

  let notify_mtu t src_ip mtu jumbo_hd = ()

  let from_same_network t ipx ipy =
    intf_of_ip_exn t ipx >>= fun intfx ->
    intf_of_ip_exn t ipy >>= fun intfy ->
    Lwt.return (intfx.dev = intfy.dev)

  let acquire_fake_dst t src_ip =
    intf_of_ip_exn t src_ip >>= fun intf ->
    Lwt.return @@ intf.acquire_fake_ip ()

  let release_fake_dst t fake_dst =
    intf_of_ip_exn t fake_dst >>= fun intf ->
    Lwt.return @@ intf.release_fake_ip fake_dst

  let register_intf t intf dispatch_fn =
    let rec drain_pkt () =
      Lwt_stream.get intf.recv_st >>= function
      | Some buf ->
          (match Frame.parse_ipv4_pkt buf with
          | Ok Frame.(Ipv4 {src; dst; ihl} as pkt) ->
              if Cstruct.len buf > intf.mtu then
                let jumbo_hd = Cstruct.sub buf 0 (ihl * 4 + 8) in
                let mtu_notification = Pkt.notify_mtu_pkt ~src:dst ~dst:src intf.mtu jumbo_hd in
                intf.send_push (Some mtu_notification);
                Lwt.return_unit
              else dispatch_fn (buf, pkt)
          | Ok Frame.Unknown | Error _ -> Log.warn (fun m -> m "unparsable pkt from %s" intf.dev)
          | Ok (_  as pkt) -> Log.warn (fun m -> m "not ipv4 pkt: %s" (Frame.fr_info pkt)))
          >>= fun () -> drain_pkt ()
      | None -> Log.warn (fun m -> m "stream from %s closed!" intf.dev) in
    t.interfaces <- IntfSet.add intf t.interfaces;
    Lwt.return drain_pkt

  let create () =
    let interfaces = IntfSet.empty in
    let intf_cache = IpMap.empty in
    {interfaces; intf_cache}
end


open Cmdliner

let usocket =
  let doc = "unix socket for the bridge to listen to" in
  Arg.(value & opt string "/var/tmp/bridge" & info ["s"; "socket"] ~doc ~docv:"SOCKET")


let logs =
  let doc = "set source-dependent logging level, eg: --logs *:info,foo:debug" in
  let src_levels = [
    `Src "bridge",    Logs.Info;
    `Src "monitor",   Logs.Info;
    `Src "connector", Logs.Debug;] in
  Arg.(value & opt (list Utils.log_threshold) src_levels & info ["l"; "logs"] ~doc ~docv:"LEVEL")

let cmd =
  let doc = "databox-bridge core component" in
  Term.(const main $ usocket $ logs),
  Term.info "bridge" ~doc ~man:[]

let () =
  Printexc.record_backtrace true;
  async_exception ();
  match Term.eval cmd with
  | `Ok t -> Lwt_main.run t
  | _ -> exit 1
