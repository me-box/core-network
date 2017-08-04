open Lwt.Infix

let bridge = Logs.Src.create "bridge" ~doc:"Bridge"
module Log = (val Logs_lwt.src_log bridge : Logs_lwt.LOG)

let hexdump_buf_debug buf =
  Log.debug (fun m ->
      let b = Buffer.create 128 in
      Cstruct.hexdump_to_buffer b buf;
      m "sent pkt(%d):%s" (Buffer.length b) (Buffer.contents b))

let is_dns_query = let open Frame in function
  | Ipv4 { payload = Udp { dst = 53; _ }; _ }
  | Ipv4 { payload = Tcp { dst = 53; _ }; _ } -> true
  | _ -> false

let names_of_query = let open Frame in function
  | Ipv4 { payload = Udp { dst = 53; payload = Payload buf}}
  | Ipv4 { payload = Tcp { dst = 53; payload = Payload buf}} ->
      let open Dns.Packet in
      let query = parse buf in
      List.map (fun {q_name; _} -> Dns.Name.to_string q_name) query.questions
  | _ -> []

let ip_of_name n =
  let open Lwt_unix in
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
    ip_of_name nx >>= fun ipx ->
    ip_of_name ny >>= fun ipy ->
    t.transport <- t.transport |> PSet.add (ipx, ipy);
    t.resolve <- t.resolve |> allow_resolve ipx ny |> allow_resolve ipy nx;
    Lwt.return_unit

  let forbidden_pair t nx ny =
    ip_of_name nx >>= fun ipx ->
    ip_of_name ny >>= fun ipy ->
    t.transport <- t.transport |> PSet.remove (ipx, ipy);
    t.resolve <- t.resolve |> forbidden_resolve ipx ny |> forbidden_resolve ipy nx;
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




module Dispatcher = struct

  module EndpMap = Map.Make(struct
      type t = Proto.endpoint
      let compare x y = Pervasives.compare x.Proto.interface y.Proto.interface
    end)

  type st_elem = Cstruct.t * Frame.t
  type t = {
    mutable endpoints: (st_elem Lwt_stream.t * (st_elem option -> unit)) EndpMap.t;
    route_cache: (Ipaddr.V4.t, Proto.endpoint) Hashtbl.t;
  }

(*
  let count_in_pkts intf in_s cnt_ref =
    let rec aux () =
      Lwt_stream.get in_s >>= function
      | Some (_, fr) ->
          Log.debug (fun m -> m "a pkt from %s" intf) >>= fun () ->
          incr cnt_ref; aux ()
      | None ->
          Log.warn (fun m -> m "%s incoming stream closed?!" intf)
          >>= Lwt.return
    in
    aux ()
*)

  let better_endpoint ip endpx endpy =
    let matched_prefix ipx ipy =
      Int32.logxor (Ipaddr.V4.to_int32 ipx) (Ipaddr.V4.to_int32 ipy)
    in
    (*smaller is better, ASSUMING highest bit are all the same*)
    if Int32.compare (matched_prefix ip endpx) (matched_prefix ip endpy) < 0 then endpx
    else endpy

  let find_push_endpoint {endpoints; route_cache} ip =
    if Hashtbl.mem route_cache ip then Hashtbl.find route_cache ip
    else begin
      (*find current best outgoing endpoint*)
      (*add to the cache, then return*)
    end


  let register_endpoint t endp in_s push_out =
    if not @@ EndpMap.mem endp t.endpoints then
      t.endpoints <- EndpMap.add endp (in_s, push_out) t.endpoints

  let create ()  =
    let endpoints = EndpMap.empty  in
    let route_cache = Hashtbl.create 7 in
    {endpoints; route_cache}

end


let rec from_endpoint conn push_in =
  Proto.Server.recv conn >>= fun buf ->
  hexdump_buf_debug buf >>= fun () ->
  Frame.parse buf |> function
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


let main path =
  Proto.Server.bind path >>= fun server ->

  let disp = Dispatcher.create () in
  let serve_endp endp conn =
    let in_s, push_in = Lwt_stream.create () in
    let out_s, push_out = Lwt_stream.create () in
    Log.info (fun m -> m "client %s made connection!" @@ Proto.endp_to_string endp) >>= fun () ->
    Dispatcher.register_endpoint disp endp in_s push_out >>= fun () ->
    Lwt.pick [
      from_endpoint conn push_in;
      to_endpoint conn out_s
    ]
  in
  Proto.Server.listen server serve_endp >>= fun () ->
  let t, _ = Lwt.task () in
  t

let () =
  let path = Sys.argv.(1) in
  let lvl = Sys.argv.(2) in
  Lwt_main.run (
    Logs.set_reporter @@ Logs_fmt.reporter ();
    Logs.set_level (match String.lowercase_ascii lvl with
      | "debug" -> Some Logs.Debug
      | _ -> Some Logs.Info);

    Log.info (fun m -> m "listen on unix socket %s" path) >>= fun () ->
    main path)
