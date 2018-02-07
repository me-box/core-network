open Lwt.Infix
open Lib_core_network

let intf = Logs.Src.create "relay" ~doc:"Bcast traffic relay"
module Log = (val Logs_lwt.src_log intf : Logs_lwt.LOG)

let existed_intf () =
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
    Log.info (fun m -> m "%s: %s" dev cidr_addr)) existed >>= fun () ->
  Lwt.return existed

let host_net host_ip existed =
  List.fold_left (fun acc (dev, cidr_addr) ->
    let _, ip = Ipaddr.V4.Prefix.of_address_string_exn cidr_addr in
    if host_ip = Ipaddr.V4.to_string ip then (dev, cidr_addr) :: acc
    else acc) [] existed
  |> fun hosts ->
    if 0 <> List.length hosts then
      let dev, cidr = List.hd hosts in
      Intf.create ~dev ~cidr
    else
      Log.err (fun m -> m "no interface with address %s found" host_ip)
      >>= fun () -> Lwt.fail_invalid_arg host_ip

let broadcast consume intf =
  let broad_dst = Ipaddr.V4.Prefix.broadcast intf.Intf.network in
  let recvfrom intf =
    Lwt_stream.get intf.Intf.recv_st >>= function
    | Some pkt ->
      let dst = Ipv4_wire.get_ipv4_dst pkt |> Ipaddr.V4.of_int32 in
      if 0 = Ipaddr.V4.compare dst broad_dst then
        let buf_len = Cstruct.len pkt in
        let pkt_len = Ipv4_wire.get_ipv4_len pkt in
        Log.debug (fun m -> m "got one broadcast pkt: %d %d" pkt_len buf_len) >>= fun () ->
        consume pkt
      else Lwt.return_unit
    | None -> Log.warn (fun m -> m "recv stream from %s closed!" intf.Intf.dev) in
  let rec loop () =
    recvfrom intf
    >>= loop in
  loop ()

(* name: absolute path *)
let open_fifo name =
  (*check for existence and file type*)
  let fd = Unix.openfile name [Unix.O_WRONLY] 0o640 in
  Lwt.return fd

let write_fifo fd buf =
  let buff = Cstruct.to_string buf in
  let len = Cstruct.len buf in
  let cnt = ref 0 in
  try
    while !cnt < len do
      let wcnt = Unix.write fd buff !cnt (len - !cnt) in
      cnt := !cnt + wcnt
    done;
    Lwt.return_unit
  with err -> Lwt.fail err

let start host_ip fd =
  existed_intf ()
  >>= host_net host_ip
  >>= fun (intf, intf_starter) ->
  broadcast (write_fifo fd) intf <&> intf_starter ()


open Cmdliner

let main host_ip fifo logs =
  Utils.Log.set_up_logs logs >>= fun () ->
  open_fifo fifo >>= fun fd ->
  start host_ip fd

let logs =
  let doc = "set source-dependent logging level, eg: --logs *:info,foo:debug" in
  let src_levels = [`Src "relay", Logs.Info] in
  Arg.(value & opt (list Utils.Log.log_threshold) src_levels & info ["l"; "logs"] ~doc ~docv:"LEVEL")

let host =
  let doc = "set host IP address of relay broadcast traffic from" in
  Arg.(required & opt (some string) None & info ["h"; "host"] ~doc ~docv:"HOST")

let fifo_name =
  let doc = "absolute path to fifo to write broadcast packet into" in
  Arg.(required & opt (some string) None & info ["f"; "file"] ~doc ~docv:"FIFO")

let cmd =
  let doc = "broadcast traffic relay from host to core-network" in
  Term.(const main $ host $ fifo_name $ logs),
  Term.info "relay" ~doc ~man:[]


let () =
  match Term.eval cmd with
  | `Ok t -> Lwt_main.run t
  | _ -> exit 1