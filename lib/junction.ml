open Lwt.Infix

let junction = Logs.Src.create "junction" ~doc:"Traffic junction"
module Log = (val Logs_lwt.src_log junction : Logs_lwt.LOG)

let hexdump_buf_debug desp buf =
  Log.warn (fun m ->
      let b = Buffer.create 4096 in
      Cstruct.hexdump_to_buffer b buf;
      m "%s len:%d pkt:%s" desp (Cstruct.len buf) (Buffer.contents b))

let pp_ip = Ipaddr.V4.pp_hum


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
  let set_local_listener t intf =
    let open Frame in
    let listener buf =
      Lwt.catch (fun () ->
      match parse buf with
      | Ok (Ethernet {dst = dst_mac; payload = Ipv4 {dst = dst_ip}})
        when 0 = Macaddr.compare dst_mac local_virtual_mac ->
          let pkt_raw = Cstruct.shift buf Ethif_wire.sizeof_ethernet in
          intf.Intf.send_push @@ Some pkt_raw;
          Lwt.return_unit
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


  let create intf =
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
    set_local_listener t intf;
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

  let service_restart po =
    let service_request_handler = fun req ->
    Lwt.catch (fun () ->
      json_of_body_exn req >>= fun obj ->
      try
        let open Ezjsonm in
        let dict = get_dict (value obj) in
        let name = List.assoc "name" dict |> get_string in
        let old_ip =
          List.assoc "old_ip" dict
          |> get_string
          |> Ipaddr.V4.of_string_exn in
        let new_ip =
          List.assoc "new_ip" dict
          |> get_string
          |> Ipaddr.V4.of_string_exn in
        Policy.substitute po name old_ip new_ip >>= fun () ->
        let status = Cohttp.Code.(`OK) in
        Lwt.return (status, `Json (`O []))
      with e -> Lwt.fail e) (fun e ->
      let msg = Printf.sprintf "/restart server err: %s" (Printexc.to_string e) in
      let status = Cohttp.Code.(`Code 500) in
      Lwt.return (status, `String msg)) >>= fun (code, body) ->
      respond' ~code body
    in
    post "/restart" service_request_handler

  let add_privileged po network =
    let add_privileged_handler = fun req ->
      Lwt.catch (fun () ->
          json_of_body_exn req >>= fun obj ->
          try
            let open Ezjsonm in
            let dict = get_dict (value obj) in
            let src_ip_str = List.assoc "src_ip" dict |> get_string in
            let src_ip = Ipaddr.V4.of_string_exn src_ip_str in
            Policy.allow_privileged_ip po src_ip >>= fun () ->
            Policy.disallow_privileged_network po network >>= fun () ->
            Lwt.return (`OK, `Json (`O []))
          with e -> Lwt.fail e) (fun e ->
          let msg = Printf.sprintf "/privileged server err: %s" (Printexc.to_string e) in
          Lwt.return (`Code 500, `String msg)) >>= fun (code, body) ->
      respond' ~code body
    in
    post "/privileged" add_privileged_handler

  let get_status =
    let status_handler = fun req -> respond' ~code:`OK (`String "active") in
    get "/status" status_handler

  let start_service t po =
   let callback = callback_of_routes [
        connect_for po;
        disconnect_for po;
        service_restart po;
        add_privileged po t.network;
        get_status;
      ] in
    start t.service ~callback


  let initialize intf policy =
    create intf >>= fun t ->
    Lwt.return @@ start_service t policy
end


module Dispatcher = struct

  type t = {
    interfaces: Interfaces.t;
    policy: Policy.t;
    nat: Nat.t;
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
      Nat.translate t.nat (src_ip, dst_ip) (buf, pkt) >>= fun (nat_src_ip, nat_dst_ip, nat_buf, nat_pkt) ->
      Log.debug (fun m -> m "Dispatcher: allowed pkt[NAT] %a -> %a => %a -> %a"
          pp_ip src_ip pp_ip dst_ip pp_ip nat_src_ip pp_ip nat_dst_ip) >>= fun () ->
      Interfaces.to_push t.interfaces nat_src_ip nat_buf
    else if Dns_service.is_dns_response pkt then Lwt.return_unit
    else Log.warn (fun m -> m "Dispatcher: dropped pkt %a -> %a" pp_ip src_ip pp_ip dst_ip)


  let create interfaces nat policy =
    {interfaces; policy; nat}
end


let create ?fifo intf_st =
  let interfaces = Interfaces.create () in
  let nat = Nat.create () in
  let policy = Policy.create interfaces nat in
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

  let rec junction_lp () =
    Lwt_stream.get intf_st >>= function
    | None -> Log.warn (fun m -> m "monitor stream closed!" )
    | Some (`Up (intf, intf_starter)) ->
        if intf.Intf.dev = "eth0" then
          Policy.allow_privileged_network policy intf.Intf.network >>= fun () ->
          Local.initialize intf policy >>= fun service_starter ->
          register_and_start intf intf_starter >>= fun () ->
          Log.info (fun m -> m "start local service on %s..." intf.Intf.dev) >>= fun () ->
          Lwt.async service_starter;
          junction_lp ()
        else if intf.dev = "eth1" then
          let network = intf.Intf.network in
          let gw = network
            |> Ipaddr.V4.Prefix.network |> Ipaddr.V4.to_int32
            |> Int32.add Int32.one |> Ipaddr.V4.of_int32 in
          Intf.set_gateway intf gw;
          Log.info (fun m -> m "set gateway for %s(%a) to %a"
              intf.Intf.dev Ipaddr.V4.Prefix.pp_hum intf.Intf.network Ipaddr.V4.pp_hum gw)
          >>= fun () ->
          register_and_start intf intf_starter >>= fun () ->
          junction_lp ()
        else
          register_and_start intf intf_starter >>= fun () ->
          junction_lp ()
    | Some (`Down dev) ->
        Interfaces.deregister_intf interfaces dev >>= fun () ->
        junction_lp ()
    in

  Policy.allow_privileged_host policy "arbiter" >>= fun () ->
  Bcast.create ?fifo interfaces >>= fun bcast_starter ->
  Lwt.return @@ fun () -> junction_lp () <&> bcast_starter ()
