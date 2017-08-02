open Lwt
open Mirage_types_lwt

let connector = Logs.Src.create "connector" ~doc:"Network Connector"
module Log = (val Logs_lwt.src_log connector : Logs_lwt.LOG)


module Make(N: NETWORK)(IP: IPV4) = struct

  let to_bridge endp n conn =
    let nf_cb = Proto.Client.send conn in
    N.listen n nf_cb >>= function
    | Ok () ->
        Log.info (fun m -> m "to_bridge ok: %s" @@ Proto.endp_to_string endp) >>= return
    | Error e ->
        Log.err (fun m -> m "to_bridge err: %a" N.pp_error e) >>= return


  let rec from_bridge n conn =
    Proto.Client.recv conn >>= fun buf ->
    N.write n buf >>= function
    | Ok () ->
        from_bridge n conn
    | Error e ->
        Log.err (fun m -> m "from bridge err: %a" N.pp_error e) >>= return


  let start n ip =
    let socket_path = Key_gen.socket_path () in

    let intf = Key_gen.interface () in
    let macaddr = N.mac n in
    let ipaddr = IP.get_ip ip |> List.hd in

    let endp = Proto.create_endp intf macaddr ipaddr in

    Proto.Client.connect socket_path endp >>= function
    | Ok conn ->
        pick [
          to_bridge endp n conn;
          from_bridge n conn;
        ] >>= fun () ->
        Proto.Client.disconnect conn
    | Error (`Msg msg) ->
        Log.err (fun m -> m "can't connect to %s: %s" socket_path msg)

end
