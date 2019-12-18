open Cmdliner
open Lib_core_network

let core = Logs.Src.create "core" ~doc:"Databox's core-network component"

module Log = (val Logs_lwt.src_log core : Logs_lwt.LOG)

let print_async_exn () =
  let hook = !Lwt.async_exception_hook in
  let hook' exn =
    Printf.printf "aysnc exception: %s\n%s" (Printexc.to_string exn)
      (Printexc.get_backtrace ()) ;
    hook exn
  in
  Lwt.async_exception_hook := hook'

let main fifo logs =
  let open Lwt.Infix in
  Utils.Log.set_up_logs logs
  >>= fun () ->
  Monitor.create ()
  >>= fun (intf_st, monitor_starter) ->
  Log.info (fun m -> m "starting interface monitor...")
  >>= fun () ->
  Lwt.async monitor_starter ;
  Lwt_unix.sleep 0.5
  >>= fun () ->
  Log.info (fun m -> m "starting junction...")
  >>= fun () ->
  Junction.create ?fifo intf_st >>= fun junction_starter -> junction_starter ()

let logs =
  let doc = "set source-dependent logging level, eg: --logs *:info,foo:debug" in
  let src_levels =
    [ (`Src "bcast", Logs.Info)
    ; (`Src "core", Logs.Info)
    ; (`Src "junction", Logs.Info)
    ; (`Src "dns", Logs.Info)
    ; (`Src "policy", Logs.Info)
    ; (`Src "NAT", Logs.Info)
    ; (`Src "monitor", Logs.Info)
    ; (`Src "interfaces", Logs.Info) ]
  in
  Arg.(
    value
    & opt (list Utils.Log.log_threshold) src_levels
    & info ["l"; "logs"] ~doc ~docv:"LEVEL")

let fifo_name =
  let doc = "absolute path to fifo to read broadcast packet from" in
  Arg.(value & opt (some string) None & info ["f"; "file"] ~doc ~docv:"FIFO")

let cmd =
  let doc = "databox-bridge core-network" in
  (Term.(const main $ fifo_name $ logs), Term.info "bridge" ~doc ~man:[])

let () =
  Printexc.record_backtrace true ;
  print_async_exn () ;
  match Term.eval cmd with `Ok t -> Lwt_main.run t | _ -> exit 1
