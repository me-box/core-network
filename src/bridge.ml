open Lwt.Infix

let bridge = Logs.Src.create "bridge" ~doc:"Bridge"
module Log = (val Logs_lwt.src_log bridge : Logs_lwt.LOG)

let hexdump_buf_debug desp buf =
  Log.debug (fun m ->
      let b = Buffer.create 128 in
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
        Log.info (fun m -> m "to resolve %s after %fs" n sleep_time) >>= fun () ->
        Lwt_unix.sleep sleep_time >>= fun () ->
        to_resolve () >>= keep_trying
    | `Resolved ip ->
        Log.info (fun m -> m "resolved: %a" pp_ip ip) >>= fun () ->
        Lwt.return ip in
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
      match resolve name with
      | Some resolved ->
          Log.info (fun m -> m "Dns_service: allowed to resolve %s" name) >>= fun () ->
          let name = Dns.Name.of_string name in
          let rrs = Dns.Packet.[{ name; cls = RR_IN; flush = false; ttl = 0l; rdata = A resolved }] in
          Lwt.return Dns.Query.({ rcode = NoError; aa = true; answer = rrs; authority = []; additional = []})
      | None ->
          Log.info (fun m -> m "Dns_service: banned to resolve %s" name) >>= fun () ->
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

  type  t = {
    mutable translation: pair PairMap.t;
    mutable rule_handles: pair PairMap.t;
  }

  let add_rule t px py =
    t.translation <- PairMap.add px py t.translation;
    let handle = fst px, snd py in
    t.rule_handles <- PairMap.add handle px t.rule_handles;
    Log.info (fun m -> m "new NAT rule: (%a -> %a) => (%a -> %a)"
                 pp_ip (fst px) pp_ip (snd px) pp_ip (fst py) pp_ip (snd py))


  let remove_rule t handle =
    (if PairMap.mem handle t.rule_handles then
       let rule_key = PairMap.find handle t.rule_handles in
       let fake_dst = snd rule_key in
       t.translation <- PairMap.remove rule_key t.translation;
       t.rule_handles <- PairMap.remove handle t.rule_handles;
       fake_dst
     else fst handle)
    |> Lwt.return

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
    let rule_handles = PairMap.empty in
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
    mutable req_queue: (Ipaddr.V4.t Lwt.u) ReqMap.t;
    mutex: Lwt_mutex.t;
  }

  let endp_to_push t dst =
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


  let to_push t dst dg =
    endp_to_push t dst >>= function
    | None ->
        Log.warn (fun m -> m "no endp to push for %a, drop" pp_ip dst)
    | Some endp ->
        let push_fn = EndpMap.find endp t.push_fn in
        push_fn (Some dg);
        Lwt.return_unit


  let rec comm_monitor t conn =
    let open Proto in
    Proto.Server.recv_comm conn >>= function
    | ACK (ip, id) ->
        Log.info (fun m -> m "ACK %a %ld" pp_ip ip id) >>= fun () ->
        Lwt_mutex.with_lock t.mutex (fun () ->
            let wakener = ReqMap.find id t.req_queue in
            Lwt.wakeup wakener ip;
            t.req_queue <- ReqMap.remove id t.req_queue;
            Lwt.return_unit) >>= fun () ->
        comm_monitor t conn
    | IP_DUP dup ->
        Log.warn (fun m -> m "DUPLICATE: %a!" pp_ip dup) >>= fun () ->
        comm_monitor t conn
    | IP_REQ _ ->
        Log.err (fun m -> m "IP_REQ from client?!") >>= fun () ->
        comm_monitor t conn

  let enqueue_req t id u =
    Lwt_mutex.with_lock t.mutex (fun () ->
        t.req_queue <- ReqMap.add id u t.req_queue;
        Lwt.return_unit)

  let _req_id = ref 0l
  let req_id () =
    let id = !_req_id in
    _req_id := Int32.pred id;
    id

  let claim_fake_dst t ip =
    let fake, u = Lwt.wait () in
    endp_to_push t ip >>= function
    | None ->
        Log.err (fun m -> m "no endp to fake dst for %a" pp_ip ip) >>= fun () ->
        Lwt.fail_with "claim_fake_dst"
    | Some endp ->
        let id = req_id () in
        let comm = Proto.IP_REQ id in
        let conn = EndpMap.find endp t.connections in
        Log.info (fun m -> m "IP_REQ %ld on %s(%a) for %a" id endp.interface pp_ip endp.ip_addr pp_ip ip) >>= fun () ->
        enqueue_req t id u >>= fun () ->
        Proto.Server.send_comm conn comm >>= fun () ->
        fake

  let register_endpoint t endp conn push =
    Lwt.async (fun () -> comm_monitor t conn);
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

  module PairSet = Set.Make(struct
      type t = pair
      let compare (xx, xy) (yx, yy) =
        let open Ipaddr.V4 in
        if compare xx yx = 0 && compare xy yy = 0 then 0
        else compare xx yy
    end)

  type t = {
    mutable transport: PairSet.t;
    mutable resolve: (string * Ipaddr.V4.t) list IpMap.t;
    endpoints: Endpoints.t;
    nat: NAT.t;
  }

  let allow_resolve t src_ip name dst_ip =
    if IpMap.mem src_ip t.resolve
    then
      let names = IpMap.find src_ip t.resolve in
      let names' = (name, dst_ip) :: (List.remove_assoc name names) in
      t.resolve <- IpMap.add src_ip names' t.resolve
    else t.resolve <- IpMap.add src_ip [name, dst_ip] t.resolve;
    Log.info (fun m -> m "allow %a to resolve %s (as %a)" pp_ip src_ip name pp_ip dst_ip)


  let allow_transport t src_ip dst_ip =
    t.transport <- PairSet.add (src_ip, dst_ip) t.transport;
    Lwt.return_unit

  let forbidden_resolve t src_ip name =
    if IpMap.mem src_ip t.resolve
    then
      let names = IpMap.find src_ip t.resolve in
      let names' = List.remove_assoc name names in
      t.resolve <- IpMap.add src_ip names' t.resolve;
      Lwt.return_unit
    else Lwt.return_unit

  let forbidden_transport t src_ip dst_ip =
    t.transport <- PairSet.remove (src_ip, dst_ip) t.transport;
    Lwt.return_unit


  let process_allowed_pair t nx ny =
    Lwt_list.map_s Dns_service.ip_of_name [nx; ny] >>= fun ips ->
    let ipx = List.hd ips
    and ipy = List.hd @@ List.tl ips in
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


  let allow_pair t nx ny =
    Lwt.async (fun () ->
        process_allowed_pair t nx ny >>= fun () ->
        Log.info (fun m -> m "Policy.allow %s <> %s" nx ny));
    Lwt.return_unit


  let forbidden_pair t nx ny =
    Dns_service.ip_of_name nx >>= fun ipx ->
    Dns_service.ip_of_name ny >>= fun ipy ->
    forbidden_resolve t ipx ny >>= fun () ->
    forbidden_resolve t ipy nx >>= fun () ->
    NAT.remove_rule t.nat (ipx, ipy) >>= fun ipy' ->
    NAT.remove_rule t.nat (ipy, ipx) >>= fun ipx' ->
    forbidden_transport t ipx ipy' >>= fun () ->
    forbidden_transport t ipy ipx' >>= fun () ->
    Lwt.return_unit


  let is_authorized_transport {transport; _} ipx ipy =
    PairSet.mem (ipx, ipy) transport

  let is_authorized_resolve t ip name =
    if IpMap.mem ip t.resolve then
      let names = IpMap.find ip t.resolve in
      if not @@ List.mem_assoc name names then None
      else Some (List.assoc name names)
    else None


  let create endpoints nat () =
    let transport = PairSet.empty in
    let resolve = IpMap.empty in
    {transport; resolve; endpoints; nat}
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

  let create () =
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
    let network, address =
      match Br_env.system_network () with
      | Some (n, a) -> n, a
      | None ->
          Lwt.ignore_result @@ Log.err (fun m -> m "required ENV for local address!");
          assert false in
    Service.make backend address >>= fun service ->
    Lwt.return {id; backend; service; network; address}

  let is_to_local {network} ip =
    Ipaddr.V4.Prefix.mem ip network

  let write_to_service t source ethertype pkt =
    let open Ethif_packet in
    let destination = Service.mac t.service in
    let hd = {source; destination; ethertype} in
    let hd = Marshal.make_cstruct hd in
    let fr = Cstruct.append hd pkt in
    Backend.write t.backend t.id fr >>= function
    | Ok () -> Lwt.return_unit
    | Error err ->
        Log.err (fun m -> m "write_to_service err: %a" Mirage_net.pp_error err)
        >>= Lwt.return


  open Service

  let allow_route po =
    let allow_handler = fun req ->
      json_of_body_exn req >>= fun obj ->
      Ezjsonm.(get_pair get_string get_string @@ value obj)
      |> fun (x, y) ->
      Lwt.catch (fun () ->
          Policy.allow_pair po x y >>= fun () ->
          let status = Cohttp.Code.(`OK) in
          Lwt.return (status, `Json (`O [])))
        (fun e ->
           let msg = Printf.sprintf "Policy.allow_pair %s %s: %s" x y (Printexc.to_string e) in
           let status = Cohttp.Code.(`Code 500) in
           Lwt.return (status, `String msg)) >>= fun (code, body) ->
      respond' ~code body
    in
    post "/connect" allow_handler

  let forbidden_route po =
    let forbidden_handler = fun req ->
      json_of_body_exn req >>= fun obj ->
      Ezjsonm.(get_pair get_string get_string @@ value obj)
      |> fun (x, y) ->
      Lwt.catch (fun () ->
          Policy.forbidden_pair po x y >>= fun () ->
          let status = Cohttp.Code.(`OK) in
          Lwt.return (status, `Json (`O [])))
        (fun e ->
           let msg = Printf.sprintf "Policy.forbidden_pair %s %s: %s" x y (Printexc.to_string e) in
           let status = Cohttp.Code.(`Code 500) in
           Lwt.return (status, `String msg)) >>= fun (code, body) ->
      respond' ~code body
    in
    post "/disconnect" forbidden_handler


  let start_service t po =
    let callback = callback_of_routes [allow_route po; forbidden_route po] in
    start t.service ~callback
end


module Dispatcher = struct

  type t = {
    endpoints: Endpoints.t;
    local: Local.t;
    policy: Policy.t;
    nat: NAT.t;
  }

  let dispatcher_mac = Macaddr.make_local (fun x -> x + 1)

  let dispatch t endp (buf, pkt) =
    Log.info (fun m -> m "in dispatch %s(%d)" (Frame.fr_info pkt) (Cstruct.len buf)) >>= fun () ->
    let src_ip, dst_ip = let open Frame in match pkt with
      | Ipv4 {src; dst; _} -> src, dst
      | _ ->
          Log.err (fun m -> m "Dispathcer: dispatch %s" (Frame.fr_info pkt)) |> Lwt.ignore_result;
          assert false in
    if Dns_service.is_dns_query pkt then
      Log.info (fun m -> m "Dispatcher: a dns query from %a" pp_ip src_ip) >>= fun () ->
      let resolve = Policy.is_authorized_resolve t.policy src_ip in
      Dns_service.process_dns_query ~resolve pkt >>= fun resp ->
      let resp = Dns_service.to_dns_response t pkt resp in
      Endpoints.to_push t.endpoints dst_ip resp
    else if Local.is_to_local t.local dst_ip then
      Log.debug (fun m -> m "Dispatcher: allowed pkt[local] %a -> %a" pp_ip src_ip pp_ip dst_ip) >>= fun () ->
      Local.write_to_service t.local dispatcher_mac Ethif_wire.IPv4 buf
    else if Policy.is_authorized_transport t.policy src_ip dst_ip then
      Log.debug (fun m -> m "Dispatcher: allowed pkt %a -> %a" pp_ip src_ip pp_ip dst_ip) >>= fun () ->
      NAT.translate t.nat (src_ip, dst_ip) (buf, pkt) >>= fun (nat_src_ip, nat_dst_ip, nat_buf, nat_pkt) ->
      Log.info (fun m -> m "Dispatcher: after NAT %a -> %a" pp_ip nat_src_ip pp_ip nat_dst_ip) >>= fun () ->
      Endpoints.to_push t.endpoints nat_dst_ip (nat_buf, nat_pkt)
    else Log.warn (fun m -> m "Dispatcher: dropped pkt %a -> %a" pp_ip src_ip pp_ip dst_ip)

(*
  let register_endpoint t endp in_s =
    if not @@ EndpMap.mem endp t.endpoints then
      t.endpoints <- EndpMap.add endp (in_s, push_out) t.endpoints;
    let rec drain_pkt () =
      Lwt_stream.get in_s >>= function
      | Some (buf, pkt) ->
          dispatch t endp (buf, pkt) >>= fun () ->
          drain_pkt ()
      | None ->
          Log.warn (fun m -> m "endpoint %s closed?!" @@ Proto.endp_to_string endp)
    in
    Lwt.return drain_pkt*)


  (*from local stack in Server*)
  let set_local_listener t =
    let open Frame in
    let listener buf =
      Lwt.catch (fun () ->
          (*hexdump_buf_debug "local listener" buf >>= fun () ->*)
      match parse buf with
      | Ok (Ethernet {dst = dst_mac; payload = (Ipv4 {dst = dst_ip} as pkt)})
        when 0 = Macaddr.compare dst_mac dispatcher_mac ->
          let pkt_raw = Cstruct.shift buf Ethif_wire.sizeof_ethernet in
          Endpoints.to_push t.endpoints dst_ip (pkt_raw, pkt)
      | Ok (Ethernet {src = tha; payload = Arp {op = `Request; spa = tpa; tpa = spa}}) ->
          let arp_resp =
            let open Arpv4_packet in
            let t = {op = Arpv4_wire.Reply; sha = dispatcher_mac; spa; tha; tpa} in
            Marshal.make_cstruct t
          in
          Local.write_to_service t.local dispatcher_mac Ethif_wire.ARP arp_resp
      | Ok fr ->
          Log.warn (fun m -> m "not ipv4 or arp request: %s, dropped" (fr_info fr))
      | Error (`Msg msg) ->
          Log.err (fun m -> m "parse pkt from local err: %s" msg))
        (fun e -> Log.err (fun m -> m "set_local_listener: %s\n%s" (Printexc.to_string e) (Printexc.get_backtrace ()))
        >>= fun () -> Lwt.fail e)
    in
    Local.Backend.set_listen_fn t.local.backend t.local.id listener

  let create local policy endpoints nat =
    {endpoints; local; policy; nat}
end


let rec from_endpoint conn push_in =
  Proto.Server.recv_pkt conn >>= fun buf ->
  (*hexdump_buf_debug "from_endpoint" buf >>= fun () ->*)
  Frame.parse_ipv4_pkt buf |> function
  | Ok fr ->
      Log.info (fun m -> m "parse_ipv4_pkt: %s" (Frame.fr_info fr)) >>= fun () ->
      push_in @@ Some (buf, fr);
      from_endpoint conn push_in
  | Error (`Msg msg) ->
      Log.warn (fun m -> m "err parsing incoming pkt %s" msg) >>= fun () ->
      from_endpoint conn push_in


let rec to_endpoint conn out_s =
  Lwt_stream.get out_s >>= function
  | Some (buf, _) ->
      (*hexdump_buf_debug "to_endpoint" buf >>= fun () ->*)
      Proto.Server.send_pkt conn buf >>= fun () ->
      to_endpoint conn out_s
  | None ->
      Log.warn (fun m -> m "output stream closed ?!")


let async_exception () =
  let hook = !Lwt.async_exception_hook in
  let hook' = fun exn ->
    Log.err (fun m -> m "aysnc exception: %s\n%s" (Printexc.to_string exn) (Printexc.get_backtrace ()))
    |> Lwt.ignore_result;
    hook exn
  in
  Lwt.async_exception_hook := hook'


type log_threshold = [`All | `Src of string] * Logs.level

module Log_config = Mirage_logs.Make(Pclock)

let set_up_logs logs =
  let set_level ~default l =
    let srcs = Logs.Src.list () in
    let default =
      try snd @@ List.find (function (`All, _) -> true | _ -> false) l
      with Not_found -> default
    in
    Logs.set_level (Some default);
    List.iter (function
      | (`All, _) -> ()
      | (`Src src, level) ->
          try
            let s = List.find (fun s -> Logs.Src.name s = src) srcs in
            Logs.Src.set_level s (Some level)
          with Not_found ->
            Fmt.(pf stdout) "%a %s is not a valid log source.\n%!"
              Fmt.(styled `Yellow string) "Warning:" src
      ) l
  in
  Pclock.connect () >>= fun pclock ->
  let reporter = Log_config.create pclock in
  set_level ~default:Logs.Info logs;
  Log_config.set_reporter reporter;
  Lwt.return_unit


let main path logs =
  set_up_logs logs >>= fun () ->
  Proto.Server.bind path >>= fun server ->
  Local.create () >>= fun local ->
  let endpoints = Endpoints.create () in
  let nat = NAT.create () in
  let policy = Policy.create endpoints nat () in
  let disp = Dispatcher.create local policy endpoints nat in
  let serve_endp endp conn =
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
      from_endpoint conn push_in;
      to_endpoint conn out_s
    ]
  in

  Dispatcher.set_local_listener disp;
  Proto.Server.listen server serve_endp >>= fun () ->
  Local.start_service local policy ()


open Cmdliner

let log_threshold =
  let enum = [
    "error"  , Logs.Error;
    "warning", Logs.Warning;
    "info"   , Logs.Info;
    "debug"  , Logs.Debug;
  ] in
  let level_of_string x =
    try List.assoc x enum
    with Not_found -> Fmt.kstrf failwith "%s is not a valid log level" x
  in
  let string_of_level x =
    try fst @@ List.find (fun (_, y) -> x = y) enum
    with Not_found -> "warning"
  in
  let parser str =
    match Astring.String.cut ~sep:":" str with
    | None            -> `Ok (`All    , level_of_string str)
    | Some ("*", str) -> `Ok (`All    , level_of_string str)
    | Some (src, str) -> `Ok (`Src src, level_of_string str)
  in
  let serialize ppf = function
  | `All  , l -> Fmt.string ppf (string_of_level l)
  | `Src s, l -> Fmt.pf ppf "%s:%s" s (string_of_level l)
  in
  parser, serialize


let usocket =
  let doc = "unix socket for the bridge to listen to" in
  Arg.(value & opt string "/var/tmp/bridge" & info ["s"; "socket"] ~doc ~docv:"SOCKET")


let logs =
  let doc = "set source-dependent logging level, eg: --logs *:info,foo:debug" in
  Arg.(value & opt (list log_threshold) [] & info ["l"; "logs"] ~doc ~docv:"LEVEL")

let cmd =
  let doc = "databox-bridge core component" in
  Term.(const main $ usocket $ logs),
  Term.info "bridge" ~doc ~man:[]

let () =
  match Term.eval cmd with
  | `Ok t -> Lwt_main.run t
  | _ -> exit 1
