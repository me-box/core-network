open Lwt.Infix

let monitor = Logs.Src.create "monitor" ~doc:"Interface monitor"
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

let set_link_mtu dev mtu =
  let comm = "ip", [|"ip"; "link"; "set"; "dev"; dev; "mtu"; string_of_int mtu|] in
  Lwt_process.exec comm >>= function
  | Unix.WEXITED 0 -> Log.info (fun m -> m "set mtu of %s to %d" dev mtu)
  | _ -> Log.warn (fun m -> m "set mtu of %s FAILED, continue" dev)

let existed_intf interfaces push_intf =
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
  |> List.rev
  |> fun existed ->
  Log.info (fun m -> m "found %d existed phy interfaces" (List.length existed)) >>= fun () ->

  Lwt_list.iter_p (fun (dev, cidr_addr) ->
      set_link_mtu dev 4000 >>= fun () ->
      Intf.create ~dev ~cidr:cidr_addr >>= fun (t, start_t) ->
      push_intf (Some (`Up (t, start_t)));
      Hashtbl.add interfaces cidr_addr dev;
      Lwt.return_unit) existed


type starter = unit -> unit Lwt.t

type intf_event = [`Up of (Intf.t * Intf.starter) | `Down of string]


let create () =
  let interfaces = Hashtbl.create 7 in
  let intf_st, push_intf = Lwt_stream.create () in

  existed_intf interfaces push_intf >>= fun () ->

  let command = "ip", [|"ip"; "monitor"; "address"|] in
  let stm = Lwt_process.pread_lines command in
  let rec monitor_lp () =
    Lwt_stream.get stm >>= function
    | None ->
        Lwt_io.printf "'ip monitor address' output stream closed!"
    | Some l ->
        (match intf_event l with
        | None -> Lwt.return_unit
        | Some (`Up (dev, cidr_addr)) ->
            Log.info (fun m -> m "link up: %s %s" dev cidr_addr) >>= fun () ->
            set_link_mtu dev 4000 >>= fun () ->
            Intf.create ~dev ~cidr:cidr_addr >>= fun (t, start_t) ->
            push_intf (Some (`Up (t, start_t)));
            Hashtbl.add interfaces cidr_addr dev;
            Lwt.return_unit
        | Some (`Down cidr_addr) ->
            let dev = Hashtbl.find interfaces cidr_addr in
            Log.info (fun m -> m "link down: %s %s" dev cidr_addr) >>= fun () ->
            Hashtbl.remove interfaces cidr_addr;
            push_intf (Some (`Down dev));
            Lwt.return_unit)
        >>= fun () -> monitor_lp ()
  in

  Lwt.return (intf_st, monitor_lp)
