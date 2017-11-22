open Lwt.Infix

let dns = Logs.Src.create "dns" ~doc:"Dns service"
module Log = (val Logs_lwt.src_log dns : Logs_lwt.LOG)

let pp_ip = Ipaddr.V4.pp_hum

let is_dns_query = let open Frame in function
  | Ipv4 { payload = Udp { dst = 53; _ }; _ }
  | Ipv4 { payload = Tcp { dst = 53; _ }; _ } -> true
  | _ -> false

let is_dns_response = let open Frame in function
  | Ipv4 { payload = Udp { src = 53; _ }; _ }
  | Ipv4 { payload = Tcp { src = 53; _ }; _ } -> true
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
  let lim = 5 in
  let rec keep_trying n cnt =
    if cnt > lim then Lwt.fail @@ Invalid_argument n else
    try_resolve n () >>= function
    | `Later n ->
        Log.info (fun m -> m "resolve %s later..." n) >>= fun () ->
        Lwt_unix.sleep 0.3 >>= fun () ->
        keep_trying n (succ cnt)
    | `Resolved (n, ip) ->
        Log.info (fun m -> m "resolved: %s %a" n pp_ip ip) >>= fun () ->
        Lwt.return ip in
  Log.info (fun m -> m "try to resolve %s..." n) >>= fun () ->
  keep_trying n 1


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
