open Lwt.Infix

let bridge = Logs.Src.create "bridge" ~doc:"Bridge"
module Log = (val Logs_lwt.src_log bridge : Logs_lwt.LOG)

module Dispatcher = struct

  type st_elem = Cstruct.t * Frame.t
  type t = {
    endpoints: (Proto.endpoint, st_elem Lwt_stream.t * (st_elem option -> unit)) Hashtbl.t;
    lookups  : (Macaddr.t, Proto.endpoint) Hashtbl.t;
    stats    : (Proto.endpoint, int ref) Hashtbl.t;
  }

  let count_in_pkts intf in_s cnt_ref =
    let rec aux () =
      Lwt_stream.get in_s >>= function
      | Some (_, _) -> incr cnt_ref; aux ()
      | None ->
          Log.warn (fun m -> m "%s incoming stream closed?!" intf)
          >>= Lwt.return
    in
    aux ()

  let register_endpoint t endp in_s push_out =
    Hashtbl.replace t.endpoints endp (in_s, push_out);
    Hashtbl.replace t.lookups endp.Proto.mac_addr endp;
    let cnt = ref 0 in
    Hashtbl.replace t.stats endp cnt;
    Lwt.async (fun () ->
      Lwt.catch (fun () -> count_in_pkts endp.Proto.interface in_s cnt)
        (fun e -> Log.err (fun m -> m "count_in_pkts err: %s" @@ Printexc.to_string e)));
    Lwt.return_unit


  let print_stats {stats; _} =
    Hashtbl.fold (fun k v acc -> (k, v) :: acc) stats []
    |> Lwt_list.iter_s (fun (endp, cnt_ref) ->
        Log.info (fun m -> m "%s: %d" (Proto.endp_to_string endp) !cnt_ref))


  let create () =
    let endpoints = Hashtbl.create 7
    and lookups = Hashtbl.create 7
    and stats = Hashtbl.create 7 in
    {endpoints; lookups; stats}
end


let rec from_endpoint conn push_in =
  Proto.Server.recv conn >>= fun buf ->
  Frame.parse buf |> function
  | Ok fr ->
      push_in @@ Some (buf, fr);
      from_endpoint conn push_in
  | Error (`Msg msg) ->
      Log.warn (fun m -> m "err parsing incoming pkt %s" msg) >>= fun () ->
      Log.debug (fun m ->
          let buffer = Buffer.create 1024 in
          Cstruct.hexdump_to_buffer buffer buf;
          m "%s" @@ Buffer.contents buffer) >>= fun () ->
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
    Log.info (fun m -> m "client %s mde connection!" @@ Proto.endp_to_string endp) >>= fun () ->
    Dispatcher.register_endpoint disp endp in_s push_out >>= fun () ->
    Lwt.pick [
      from_endpoint conn push_in;
      to_endpoint conn out_s
    ] >>= fun () ->
    Dispatcher.print_stats disp
  in
  Proto.Server.listen server serve_endp >>= fun () ->
  let t, _ = Lwt.task () in
  t


let () =
  let path = Sys.argv.(1) in
  Lwt_main.run (
    Log.info (fun m -> m "listen on unix socket %s" path) >>= fun () ->
    main path)
