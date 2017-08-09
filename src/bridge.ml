open Lwt.Infix

let bridge = Logs.Src.create "bridge" ~doc:"Bridge"
module Log = (val Logs_lwt.src_log bridge : Logs_lwt.LOG)

let hexdump_buf_debug buf =
  Log.debug (fun m ->
      let b = Buffer.create 128 in
      Cstruct.hexdump_to_buffer b buf;
      m "len:%d pkt:%s" (Cstruct.len buf) (Buffer.contents b))

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


  let ip_of_name n =
    let open Lwt_unix in
    (*using system resolver*)
    gethostbyname n >>= fun {h_addr_list; _} ->
    h_addr_list
    |> Array.to_list
    |> List.map (fun addr ->
        Unix.string_of_inet_addr addr
        |> Ipaddr.V4.of_string_exn)
    |> fun ips ->
    if List.length ips <> 1
    then
      let ips_str = String.concat " " @@ List.map Ipaddr.V4.to_string ips in
      Log.warn (fun m -> m "found ip for %s: %s" n ips_str) >>= fun () ->
      Lwt.return @@ List.hd ips
    else
    Lwt.return @@ List.hd ips


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


  let process_dns_query ~predicate pkt =
    let open Dns in
    query_of_pkt pkt >>= fun query ->
    begin
      let names = Packet.(List.map (fun {q_name; _} -> q_name) query.questions) in
      let name = List.hd names |> Name.to_string in
      if predicate name then
        Log.info (fun m -> m "Dns_service: allowed to resolve %s" name) >>= fun () ->
        ip_of_name name >>= fun resolved ->
        let name = Dns.Name.of_string name in
        let rrs = Dns.Packet.[{ name; cls = RR_IN; flush = false; ttl = 0l; rdata = A resolved }] in
        Lwt.return Dns.Query.({ rcode = NoError; aa = true; answer = rrs; authority = []; additional = []})
      else
      Log.info (fun m -> m "Dns_service: banned to resolve %s" name) >>= fun () ->
      Lwt.return Query.({rcode = Packet.NXDomain; aa = true; answer = []; authority = []; additional = []})
    end >>= fun answer ->
    let resp = Query.response_of_answer query answer in
    Lwt.return @@ Packet.marshal resp
end


module RMap = Map.Make(struct
    type t = Ipaddr.V4.t
    let compare = Ipaddr.V4.compare
  end)

module Policy = struct

  type p = Ipaddr.V4.t * Ipaddr.V4.t
  module PSet = Set.Make(struct
      type t = p
      let compare (xx, xy) (yx, yy) =
        let open Ipaddr.V4 in
        if (compare xx yx = 0 && compare xy yy = 0)
        || (compare xx yy = 0 && compare xy yx = 0) then 0
        else compare xx yy
    end)

  type t = {
    mutable transport: PSet.t;
    mutable resolve: string list RMap.t;
  }

  let allow_resolve ip n resolve =
    if RMap.mem ip resolve
    then
      let names = RMap.find ip resolve in
      if List.mem n names then resolve
      else RMap.add ip (n :: names) @@ RMap.remove ip resolve
    else RMap.add ip [n] resolve

  let forbidden_resolve ip n resolve =
    if RMap.mem ip resolve
    then
      let names = RMap.find ip resolve in
      if List.mem n names then
        let names' = List.filter ((<>) n) names in
        RMap.add ip names' @@ RMap.remove ip resolve
      else resolve
    else resolve


  let allow_pair t nx ny =
    Dns_service.ip_of_name nx >>= fun ipx ->
    Dns_service.ip_of_name ny >>= fun ipy ->
    t.transport <- t.transport |> PSet.add (ipx, ipy);
    t.resolve <- t.resolve |> allow_resolve ipx ny |> allow_resolve ipy nx;
    Log.info (fun m -> m "Policy.allow %s <> %s" nx ny) >>= fun () ->
    Lwt.return_unit

  let forbidden_pair t nx ny =
    Dns_service.ip_of_name nx >>= fun ipx ->
    Dns_service.ip_of_name ny >>= fun ipy ->
    t.transport <- t.transport |> PSet.remove (ipx, ipy);
    t.resolve <- t.resolve |> forbidden_resolve ipx ny |> forbidden_resolve ipy nx;
    Log.info (fun m -> m "Policy.forbidden %s <> %s" nx ny) >>= fun () ->
    Lwt.return_unit

  let is_authorized_transport {transport; _} ipx ipy =
    PSet.mem (ipx, ipy) transport

  let is_authorized_resolve {resolve; _} ip n =
    RMap.mem ip resolve && List.mem n @@ RMap.find ip resolve

  let create () =
    let transport = PSet.empty in
    let resolve = RMap.empty in
    {transport; resolve}
end


module Local = struct

  module Backend = Basic_backend.Make
  module Service = Server.Make(Backend)

  type t = {
    id: int;
    backend: Backend.t;
    service: Service.t;
  }

  let create service_ip =
    let backend = Backend.create () in
    let id =
      match Backend.register backend with
      | `Ok id -> id
      | `Error err ->
          Log.err (fun m -> m "Backend.register err: %a" Mirage_net.pp_error err)
          |> Lwt.ignore_result; -1
    in
    Service.make backend service_ip >>= fun service ->
    Lwt.return {id; backend; service}

  let is_to_service {service} pkt =
    let open Frame in
    let service_ip = Service.ip service in
    match pkt with
    | Ipv4 { dst; payload = Tcp _} when 0 = Ipaddr.V4.compare dst service_ip -> true
    |_ -> false


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


  let start_service t po =
    let open Service in
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
    let allow_route = post "/connect" allow_handler in

    let forbidden_handler = fun req ->
      json_of_body_exn req >>= fun obj ->
      Ezjsonm.(get_pair get_string get_string @@ value obj)
      |> fun (x, y) ->
      Lwt.catch (fun () ->
          Policy.forbidden_pair po x y >>= fun () ->
          let status = Cohttp.Code.(`OK) in
          Lwt.return (status, `Json (`O [])))
        (fun e ->
           let msg = Printf.sprintf "Policy.allow_pair %s %s: %s" x y (Printexc.to_string e) in
           let status = Cohttp.Code.(`Code 500) in
           Lwt.return (status, `String msg)) >>= fun (code, body) ->
      respond' ~code body
    in
    let forbidden_route = post "/disconnect" forbidden_handler in

    let callback = callback_of_routes [allow_route; forbidden_route] in
    start t.service ~callback
end


module Dispatcher = struct

  module EndpMap = Map.Make(struct
      type t = Proto.endpoint
      let compare x y = Pervasives.compare x.Proto.interface y.Proto.interface
    end)

  type st_elem = Cstruct.t * Frame.t
  type t = {
    mutable endpoints: (st_elem Lwt_stream.t * (st_elem option -> unit)) EndpMap.t;
    route_cache: (Ipaddr.V4.t, Proto.endpoint) Hashtbl.t;
    local: Local.t;
  }

  let dispatcher_mac = Macaddr.make_local (fun x -> x + 1)

  let better_endpoint ip endpx endpy =
    let matched_prefix ipx ipy =
      Int32.logxor (Ipaddr.V4.to_int32 ipx) (Ipaddr.V4.to_int32 ipy)
    in
    (*smaller is better, ASSUMING highest bit(s) are all the same*)
    if Int32.compare
        (matched_prefix ip endpx.Proto.ip_addr)
        (matched_prefix ip endpy.Proto.ip_addr) < 0
    then endpx
    else endpy

  let find_push_endpoint {endpoints; route_cache} ip =
    if Hashtbl.mem route_cache ip then Hashtbl.find route_cache ip
    else begin
      let local_endp = Proto.{
          interface = "local";
          mac_addr = Macaddr.broadcast; (*blah*)
          ip_addr = Ipaddr.V4.localhost;
        } in
      EndpMap.fold (fun endp _ push_endp ->
          better_endpoint ip endp push_endp) endpoints local_endp
      |> fun push_endpoint ->
      Hashtbl.replace route_cache ip push_endpoint;
      push_endpoint
    end


  let dispatch t po endp (buf, pkt) =
    let src_ip, dst_ip = let open Frame in match pkt with
      | Ipv4 {src; dst; _} -> src, dst
      | _ ->
          Log.err (fun m -> m "Dispathcer: dispatch %s" (Frame.fr_info pkt)) |> Lwt.ignore_result;
          assert false in
    if Dns_service.is_dns_query pkt then
      Log.info (fun m -> m "Dispatcher: a dns query from %a" Ipaddr.V4.pp_hum src_ip) >>= fun () ->
      let predicate = Policy.is_authorized_resolve po src_ip in
      Dns_service.process_dns_query ~predicate pkt >>= fun resp ->
      let resp_buf, resp_pkt = Dns_service.to_dns_response t pkt resp in
      let _, push_fn = EndpMap.find endp t.endpoints in
      push_fn @@ Some (resp_buf, resp_pkt);
      Lwt.return_unit
    else if Policy.is_authorized_transport po src_ip dst_ip then
      if Local.is_to_service t.local pkt then
        Log.debug (fun m -> m "Dispatcher: allowed pkt[local] %a -> %a" Ipaddr.V4.pp_hum src_ip Ipaddr.V4.pp_hum dst_ip) >>= fun () ->
        Local.write_to_service t.local dispatcher_mac Ethif_wire.IPv4 buf
      else begin
        Log.debug (fun m -> m "Dispatcher: allowed pkt %a -> %a" Ipaddr.V4.pp_hum src_ip Ipaddr.V4.pp_hum dst_ip) >>= fun () ->
        let push_endp = find_push_endpoint t dst_ip in
        let _, push_fn = EndpMap.find push_endp t.endpoints in
        push_fn @@ Some (buf, pkt);
        Lwt.return_unit
      end
    else Log.warn (fun m -> m "Dispatcher: dropped pkt %a -> %a" Ipaddr.V4.pp_hum src_ip Ipaddr.V4.pp_hum dst_ip)


  let register_endpoint t po endp in_s push_out =
    if not @@ EndpMap.mem endp t.endpoints then
      t.endpoints <- EndpMap.add endp (in_s, push_out) t.endpoints;
    let rec drain_pkt () =
      Lwt_stream.get in_s >>= function
      | Some (buf, pkt) ->
          dispatch t po endp (buf, pkt)
          >>= drain_pkt
      | None ->
          Log.warn (fun m -> m "endpoint %s closed?!" @@ Proto.endp_to_string endp)
    in
    (*need a handle here*)
    Lwt.async drain_pkt


  (*from local stack in Server*)
  let set_local_listener t =
    let open Frame in
    let listener buf =
      match parse buf with
      | Ok (Ethernet {dst = dst_mac; payload = (Ipv4 {dst = dst_ip} as pkt)})
        when 0 = Macaddr.compare dst_mac dispatcher_mac ->
          let push_endp = find_push_endpoint t dst_ip in
          let _, push_fn = EndpMap.find push_endp t.endpoints in
          let pkt_raw = Cstruct.shift buf Ethif_wire.sizeof_ethernet in
          push_fn @@ Some (pkt_raw, pkt);
          Lwt.return_unit
      | Ok (Ethernet {src = tha; payload = Arp {op = `Request}}) ->
          let arp_resp =
            let open Arpv4_packet in
            let tpa = Local.Service.ip t.local.service in
            let t = {op = Arpv4_wire.Reply; sha = dispatcher_mac; spa = Ipaddr.V4.any; tha; tpa} in
            Marshal.make_cstruct t
          in
          Local.write_to_service t.local dispatcher_mac Ethif_wire.ARP arp_resp
      | Ok fr ->
          Log.warn (fun m -> m "not ipv4 or arp request: %s, dropped" (fr_info fr))
      | Error (`Msg msg) ->
          Log.err (fun m -> m "parse pkt from local err: %s" msg)
    in
    Local.Backend.set_listen_fn t.local.backend t.local.id listener

  let create local  =
    let endpoints = EndpMap.empty  in
    let route_cache = Hashtbl.create 7 in
    {endpoints; route_cache; local}
end


let rec from_endpoint conn push_in =
  Proto.Server.recv conn >>= fun buf ->
  (*hexdump_buf_debug buf >>= fun () ->*)
  Frame.parse_ipv4_pkt buf |> function
  | Ok fr ->
      push_in @@ Some (buf, fr);
      from_endpoint conn push_in
  | Error (`Msg msg) ->
      Log.warn (fun m -> m "err parsing incoming pkt %s" msg) >>= fun () ->
      from_endpoint conn push_in


let rec to_endpoint conn out_s =
  Lwt_stream.get out_s >>= function
  | Some (buf, _) ->
      Proto.Server.send conn buf >>= fun () ->
      to_endpoint conn out_s
  | None ->
      Log.warn (fun m -> m "output stream closed ?!")


let main path cm_intf =
  Proto.Server.bind path >>= fun server ->
  Local.create cm_intf >>= fun local ->
  let disp = Dispatcher.create local in
  let policy = Policy.create () in
  let serve_endp endp conn =
    let in_s, push_in = Lwt_stream.create () in
    let out_s, push_out = Lwt_stream.create () in
    Log.info (fun m -> m "client %s made connection!" @@ Proto.endp_to_string endp) >>= fun () ->
    Dispatcher.register_endpoint disp policy endp in_s push_out;
    Lwt.pick [
      from_endpoint conn push_in;
      to_endpoint conn out_s
    ]
  in

  Dispatcher.set_local_listener disp;
  Proto.Server.listen server serve_endp >>= fun () ->
  Local.start_service local policy ()


let () =
  let path = Sys.argv.(1) in
  let lvl = Sys.argv.(2) in
  let cm_intf = Sys.argv.(3) |> Ipaddr.V4.of_string_exn in
  Lwt_main.run (
    Logs.set_reporter @@ Logs_fmt.reporter ();
    Logs.set_level (match String.lowercase_ascii lvl with
      | "debug" -> Some Logs.Debug
      | _ -> Some Logs.Info);

    Log.info (fun m -> m "listen on unix socket %s" path) >>= fun () ->
    main path cm_intf)
