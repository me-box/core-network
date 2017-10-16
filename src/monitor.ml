open Lwt.Infix

let monitor = Logs.Src.create "monitor" ~doc:"Connector monitor"
module Log = (val Logs_lwt.src_log monitor : Logs_lwt.LOG)

let intf_event l =
  let open Re in
  let up = "(eth[0-9]+).* (([0-9]+.){3}[0-9]+/[0-9]+) .* eth[0-9]+" in
  let down = "Deleted.* (([0-9]+.){3}[0-9]+/[0-9]+) " in
  let regex = Printf.sprintf "(%s)|(%s)" up down in
  try
    let groups =
      let re = Re_posix.(regex |> re |> compile) in
      exec re l |> Group.all
    in
    if groups.(2) <> "" && groups.(3) <> "" then
      let link = groups.(2) and addr = groups.(3) in
      Some (`Up (link, addr))
    else
      let addr = groups.(6) in
      Some (`Down addr)
  with Not_found -> None


let existed_intf t =
  let command = "ip", [|"ip"; "address"; "show"|] in
  let st = Lwt_process.pread_lines command in
  Lwt_stream.to_list st >>= fun lines ->
  let regex = "inet (([0-9]+.){3}[0-9]+/[0-9]+) .*(eth[0-9]+)$" in
  let re = Re_posix.(regex |> re |> compile) in
  List.fold_left (fun acc line ->
      try let groups = Re.exec re line |> Re.Group.all in
        let dev = groups.(3) and addr = groups.(1) in
        (dev, addr) :: acc
      with Not_found -> acc) [] lines
  |> fun existed ->
  Log.info (fun m -> m "found %d existed phy interfaces" (List.length existed)) >>= fun () ->

  Lwt_list.iter_p (fun (dev, addr) ->
      Connector.create dev addr >>= function
      | Ok (conn, start) ->
          Hashtbl.add t addr (dev, conn);
          Lwt.async start;
          Lwt.return_unit
      | Error () -> Lwt.return_unit) existed



let start () =
  (* (ip, interface name * client connection) Hashtbl.t *)
  let connectors = Hashtbl.create 7 in

  let command = "ip", [|"ip"; "monitor"; "address"|] in
  let stm = Lwt_process.pread_lines command in
  let rec m () =
    Lwt_stream.get stm >>= function
    | None ->
        Lwt_io.printf "closed!"
    | Some l ->
        match intf_event l with
        | None ->  m ()
        | Some (`Up (dev, addr)) ->
            Log.info (fun m -> m "link up: %s %s" dev addr) >>= fun () ->
            Connector.create dev addr >>= fun connector ->
            if Rresult.R.is_ok connector then begin
              let conn, start = Rresult.R.get_ok connector in
              Hashtbl.add connectors addr (dev, conn);
              Lwt.async start end;
            m ()
        | Some (`Down addr) ->
            let dev, conn = Hashtbl.find connectors addr in
            Log.info (fun m -> m "link down: %s %s" dev addr) >>= fun () ->
            Hashtbl.remove connectors addr;
            Connector.destroy conn >>= fun () ->
            m ()
  in

  existed_intf connectors >>= fun () ->
  Log.info (fun m -> m "start monitoring for phy intf event...") >>= fun () ->
  m ()
