open Cmdliner

let core = Logs.Src.create "core" ~doc:"Databox's core-network component"
module Log = (val Logs_lwt.src_log core : Logs_lwt.LOG)

let print_async_exn () =
  let hook = !Lwt.async_exception_hook in
  let hook' exn =
    Printf.printf "aysnc exception: %s\n%s" (Printexc.to_string exn) (Printexc.get_backtrace ());
    hook exn
  in
  Lwt.async_exception_hook := hook'


let main logs =
  let open Lwt.Infix in
  Utils.set_up_logs logs >>= fun () ->
  Monitor.create () >>= fun (intf_st, monitor_starter) ->
  Log.info (fun m -> m "starting interface monitor...") >>= fun () ->
  Lwt.async monitor_starter;
  Lwt_unix.sleep 0.5 >>= fun () ->
  Log.info (fun m -> m "starting junction...") >>= fun () ->
  Junction.create intf_st >>= fun junction_starter ->
  junction_starter ()


let logs =
  let doc = "set source-dependent logging level, eg: --logs *:info,foo:debug" in
  let src_levels = [
    `Src "core",     Logs.Info;
    `Src "junction", Logs.Info;
    `Src "dns",      Logs.Info;
    `Src "policy",   Logs.Info;
    `Src "NAT",      Logs.Info;
    `Src "monitor",  Logs.Info;] in
  Arg.(value & opt (list Utils.log_threshold) src_levels & info ["l"; "logs"] ~doc ~docv:"LEVEL")

let cmd =
  let doc = "databox-bridge core-network" in
  Term.(const main $ logs),
  Term.info "bridge" ~doc ~man:[]

let () =
  Printexc.record_backtrace true;
  print_async_exn ();
  match Term.eval cmd with
  | `Ok t -> Lwt_main.run t
  | _ -> exit 1
