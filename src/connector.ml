open Lwt.Infix
open Mirage_types_lwt

let connector = Logs.Src.create "connector" ~doc:"Network Connector"
module Log = (val Logs_lwt.src_log connector : Logs_lwt.LOG)

module Ethif = Ethif.Make(Netif)
module Arpv4 = Arpv4.Make(Ethif)(Mclock)(OS.Time)

module Make(N: NETWORK)(E: ETHIF)(Arp: ARP) = struct

  type ip_pool = {
    mutable free_ips: Ipaddr.V4.t list;
    mutable used_ips: Ipaddr.V4.t list;
    probes: (Ipaddr.V4.t, (unit, unit) result Lwt.u) Hashtbl.t;
    mutex: Lwt_mutex.t;
  }

  let _free_ip_cnt = 5
  let _detect_duplicates_sleep = 60. (* s *)
  let _probe_timeout = 0.5
  let _interface = ref ""

  let pp_ip = Ipaddr.V4.pp_hum

  let create_ipp () =
    let probes = Hashtbl.create 7 in
    let mutex = Lwt_mutex.create () in
    {free_ips = []; used_ips = []; probes; mutex}

  let count_free ipp =
    Lwt_mutex.with_lock ipp.mutex (fun () ->
        Lwt.return @@ List.length ipp.free_ips)

  let put_ip ipp ip =
    Lwt_mutex.with_lock ipp.mutex (fun () ->
        if not @@ List.mem ip ipp.free_ips then ipp.free_ips <- ipp.free_ips @ [ip];
        Lwt.return_unit) >>= fun () ->
    Log.debug (fun m -> m "%s got free ip %a" !_interface pp_ip ip)

  let use_ip ipp () =
    Lwt_mutex.with_lock ipp.mutex (fun () ->
        let cnt = List.length ipp.free_ips in
        if cnt < 1 then Lwt.return (Error ()) else
        let ip = List.hd ipp.free_ips in
        ipp.free_ips <- (List.tl ipp.free_ips);
        ipp.used_ips <- ip :: ipp.used_ips;
        Lwt.return (Ok ip))
    >>= fun ip ->
    Lwt.return ip


  let return_ip ipp ip =
    Lwt_mutex.with_lock ipp.mutex (fun () ->
        if List.mem ip ipp.used_ips then begin
          ipp.used_ips <- List.filter (fun ip' -> 0 <> Ipaddr.V4.compare ip' ip) ipp.used_ips;
          ipp.free_ips <- ip :: ipp.free_ips end;
        Lwt.return_unit)


  let send_probe ipp eth arp ip =
    let probe = Arpv4_packet.{
      op = Arpv4_wire.Request;
      sha = E.mac eth;
      spa = Arp.get_ips arp |> List.hd;
      tha = Macaddr.broadcast;
      tpa = ip;} in
    let eth_hd = Ethif_packet.{
      source = E.mac eth;
      destination = Macaddr.broadcast;
      ethertype = Ethif_wire.ARP;} in
    let buf = Cstruct.concat [
        Ethif_packet.Marshal.make_cstruct eth_hd;
        Arpv4_packet.Marshal.make_cstruct probe;] in

    let found, u = Lwt.wait () in
    Lwt_mutex.with_lock ipp.mutex (fun () ->
        Lwt.return @@ Hashtbl.add ipp.probes ip u) >>= fun () ->
    E.write eth buf >>= (function
      | Ok () -> Lwt.pick [found; Lwt_unix.sleep _probe_timeout >>= Lwt_result.fail]
      | Error _ -> Lwt_result.fail ())
    >>= function
    | Ok () ->
        Log.info (fun m -> m "found ip %a on network" pp_ip ip)
        |> Lwt_result.ok
    | Error () ->
        Lwt_mutex.with_lock ipp.mutex (fun () ->
            Lwt_result.fail @@ Hashtbl.remove ipp.probes ip)


  let delete_duplicated ~delete_used ip ipp cond =
    Lwt_mutex.with_lock ipp.mutex (fun () ->
        let free_ips' =
          List.filter (fun free -> 0 <> Ipaddr.V4.compare ip free) ipp.free_ips in
        if List.length free_ips' < List.length ipp.free_ips then begin
          ipp.free_ips <- free_ips';
          Lwt_condition.signal cond () end;
        Lwt.return_unit) >>= fun () ->

    Lwt_mutex.with_lock ipp.mutex (fun () ->
        Lwt.return ipp.used_ips)
    >>= fun used_ips ->
    if List.mem ip used_ips then
      delete_used ip >>= fun () ->
      Lwt_mutex.with_lock ipp.mutex (fun () ->
          let used_ips' =
            List.filter (fun used -> 0 <> Ipaddr.V4.compare ip used) ipp.used_ips in
          ipp.used_ips <- used_ips';
          Lwt.return_unit)
    else Lwt.return_unit


  let detect_duplicates ~delete_used ipp eth arp cond =
    Lwt_mutex.with_lock ipp.mutex (fun () ->
        Lwt.return ipp.used_ips)
    >>= Lwt_list.iter_p (fun ip ->
        send_probe ipp eth arp ip >>= function
        | Ok () ->
            Log.warn (fun m -> m "duplicate detected: %a" Ipaddr.V4.pp_hum ip) >>= fun () ->
            delete_duplicated ~delete_used ip ipp cond
        | Error () -> Lwt.return_unit)

  let populate_pool ipp eth arp cond Proto.({interface; ip_addr; netmask}) =
    let network =
      let prefix = Ipaddr.V4.Prefix.make netmask ip_addr in
      Ipaddr.V4.Prefix.network prefix in
    let last_added =
      let net = Ipaddr.V4.to_int32 network in
      ref (Int32.(add net (shift_left one (32 - netmask) |> pred))) in
    let next () =
      let next = Int32.(sub !last_added one) in
      last_added := next;
      Ipaddr.V4.of_int32 next in

    let rec count_and_put () =
      count_free ipp >>= fun cnt ->
      if cnt < _free_ip_cnt then
        let candidate = next () in
        send_probe ipp eth arp candidate >>= function
        | Ok () -> count_and_put ()
        | Error () ->
            put_ip ipp candidate >>= fun () ->
            count_and_put ()
      else
      Log.info (fun m -> m "%s pool full of %d free IPs" interface cnt) >>= fun () ->
      Lwt_condition.wait cond >>= fun () ->
      Log.info (fun m -> m "%s free IP used, start collecting new..." interface) >>= fun () ->
      count_and_put ()
    in
    count_and_put ()


  let drain_pool ipp eth arp cond conn =
    let open Proto in
    let serv_ip_req () =
      let rec provision_ip () =
        Client.recv_comm conn >>= function
        | ACK _ | IP_DUP _ ->
            Log.err (fun m -> m "provision ip: not IP_REQ") >>= fun () ->
            provision_ip ()
        | IP_RTN rtn ->
            return_ip ipp rtn >>= fun () ->
            Lwt_condition.signal cond ();
            provision_ip ()
        | IP_REQ seq ->
            use_ip ipp () >>= function
            | Ok ip ->
                Client.send_comm conn (ACK (ip, seq)) >>= fun () ->
                Lwt_condition.signal cond ();
                Arp.add_ip arp ip >>= fun () ->
                Log.info (fun m -> m "%s used ip %a" !_interface pp_ip ip) >>= fun () ->
                provision_ip ()
            | Error () ->
                Log.warn (fun m -> m "not enough ip in pool! drop req %ld" seq) >>= fun () ->
                provision_ip () in
      Lwt.catch provision_ip (function
        | Lwt_stream.Empty -> Lwt.return_unit
        | exn -> Lwt.fail exn) in

    let delete_used arp ip =
      Client.send_comm conn (IP_DUP ip) >>= fun () ->
      Arp.remove_ip arp ip in
    let rec detect_dup_loop () =
      detect_duplicates ~delete_used:(delete_used arp) ipp eth arp cond >>= fun () ->
      Lwt_unix.sleep _detect_duplicates_sleep >>= fun () ->
      detect_dup_loop () in

    serv_ip_req () <&> detect_dup_loop ()


  let maintain_ipp ipp eth arp conn endp =
    let cond = Lwt_condition.create () in
    populate_pool ipp eth arp cond endp <&> drain_pool ipp eth arp cond conn


  let hexdump_buf_debug desp buf =
    Log.debug (fun m ->
        let b = Buffer.create 128 in
        Cstruct.hexdump_to_buffer b buf;
        m "%s len:%d pkt:%s" desp (Cstruct.len buf) (Buffer.contents b))

  let drop_pkt (_: Cstruct.t) = Lwt.return_unit

  let is_ipv4_multicast buf =
    let dst = Cstruct.BE.get_uint32 buf 16 |> Ipaddr.V4.of_int32 in
    Ipaddr.V4.is_multicast dst


  let to_bridge conn buf =
    Lwt.catch
      (fun () ->
         if is_ipv4_multicast buf
         then Lwt.return_unit
         else
         Proto.Client.send_pkt conn buf)
      (fun e ->
         let msg = Printf.sprintf "to_bridge err: %s" @@ Printexc.to_string e in
         Log.err (fun m -> m "%s" msg) >>= fun () ->
         hexdump_buf_debug "to_bridge" buf)


  let rec from_bridge eth arp conn =
    Lwt.catch (fun () ->
        Proto.Client.recv_pkt conn >>= fun buf ->

        let dst_ipaddr = Cstruct.BE.get_uint32 buf 16 |> Ipaddr.V4.of_int32 in
        Arp.query arp dst_ipaddr >>= function
        | Ok destination ->
            let eth_hd =
              let source = E.mac eth in
              let ethertype = Ethif_wire.IPv4 in
              Ethif_packet.(Marshal.make_cstruct {source; destination; ethertype})
            in
            let buf = Cstruct.append eth_hd buf in
            (E.write eth buf >>= function
              | Ok () ->
                  from_bridge eth arp conn
              | Error e ->
                  Log.err (fun m -> m "%s from bridge E.write: %a" !_interface E.pp_error e)
                  >>= fun () -> from_bridge eth arp conn)
        | Error e ->
            Log.err (fun m -> m "from bridge Arp.query: %a" Arp.pp_error e)) (function
      | Lwt_stream.Empty -> Lwt.return_unit
      | exn -> Lwt.fail exn)


  let intercept_probe_reply ipp arp buf =
    let open Arpv4_packet in
    Lwt_mutex.with_lock ipp.mutex (fun () ->
    match Unmarshal.of_cstruct buf with
    | Ok {op = Arpv4_wire.Reply; spa = ip} when Hashtbl.mem ipp.probes ip ->
        let u = Hashtbl.find ipp.probes ip in
        Lwt.wakeup u (Ok ());
        Lwt.return @@ Hashtbl.remove ipp.probes ip
    | _ -> Lwt.return_unit)
    >>= fun () -> Arp.input arp buf


  let forward_pkt ipp nf eth arp conn endp =
    let to_bridge eth arp conn  =
      (*sendint ip packet to bridge, not ethernet frame*)
      let ipv4 = to_bridge conn in
      let arpv4 = intercept_probe_reply ipp arp in
      let ipv6 = drop_pkt in
      let fn = E.input ~arpv4 ~ipv4 ~ipv6 eth in
      let aux () =
        N.listen nf fn >>= function
        | Ok () ->
            Log.info (fun m -> m "to_bridge ok: %s" @@ Proto.endp_to_string endp)
        | Error e ->
            Log.err (fun m -> m "to_bridge err: %a" N.pp_error e) in
      aux ()
    in

    Lwt.pick [
      to_bridge eth arp conn;
      from_bridge eth arp conn;]

  let start nf eth arp conn endp () =
    let () = _interface := endp.Proto.interface in
    let ipp = create_ipp () in
    Lwt.pick [
      maintain_ipp ipp eth arp conn endp;
      forward_pkt ipp nf eth arp conn endp;]

end

let socket_path = "/var/tmp/bridge"

let create dev addr =
  let network, ip = Ipaddr.V4.Prefix.of_address_string_exn addr in
  let netmask = Ipaddr.V4.Prefix.bits network in
  Netif.connect dev >>= fun net ->
  let mtu = Netif.mtu net in
  let mac = Netif.mac net in
  let endp = Proto.create_endp dev mac mtu ip netmask in
  Proto.Client.connect socket_path endp >>= function
  | Ok conn ->
      Mclock.connect () >>= fun mclock ->
      Ethif.connect ~mtu net >>= fun ethif ->
      Arpv4.connect ethif mclock >>= fun arp ->
      Arpv4.set_ips arp [ip] >>= fun () ->
      let module M = Make(Netif)(Ethif)(Arpv4) in
      Lwt.return_ok (conn, M.start net ethif arp conn endp)
  | Error (`Msg msg) ->
      Log.err (fun m -> m "can't connect to %s: %s" socket_path msg) >>= fun () ->
      Lwt.return_error ()

let destroy conn = Proto.Client.disconnect conn
