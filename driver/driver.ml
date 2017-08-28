open Lwt.Infix


let driver = Logs.Src.create "driver" ~doc:"Connector driver"
module Log = (val Logs_lwt.src_log driver : Logs_lwt.LOG)


let command = "ip", [|"ip"; "monitor"; "address"|]

let if_up l =
  let open Re in
  let dev = seq [bow; str "eth"; rep1 digit; eow] in
  let addr = seq [bow; rep1 digit; repn (seq [char '.'; rep1 digit]) 3 (Some 3); char '/'; rep1 digit; eow] in
  let t = seq [group dev; rep notnl; group addr] in
  let re = compile t in
  let groups = all re l in

  if 0 = List.length groups then None
  else begin
    assert (1 = List.length groups);
    let group = List.hd groups in
    let arr = Group.all_offset group in
    let dev =
      let dev_s, dev_e = Array.get arr 1 in
      String.sub l dev_s (dev_e - dev_s )
    in
    let addr =
      let addr_s, addr_e = Array.get arr 2 in
      String.sub l addr_s (addr_e - addr_s)
    in
    Some (dev, addr)
  end


let fill_config_tmpl config dev addr =
  let open Bos.OS in
  let open Rresult in
  let open Re in
  File.read config
  >>| replace_string (str "%%DEVICE%%" |> compile) ~by:dev
  >>| replace_string (str "%%ADDRESS%%" |> compile) ~by:addr


let dir_of_dev dev = "connector_" ^ dev

let create_connector dev addr =
  let open Bos.OS in
  let open Rresult in
  let open Fpath in
  (Dir.user ()
   >>= fun user_path ->
   let config_tmpl = user_path / "core-bridge" / "driver" / "config.ml.tmpl" in
   fill_config_tmpl config_tmpl dev addr
   >>| fun config_cont ->
   let connector = user_path / "core-bridge" / "driver" / "connector" in
   let target_connector = user_path / (dir_of_dev dev) in
   let cp = "cp", [|"cp"; "-R"; Fpath.to_string connector; Fpath.to_string target_connector|] in
   Lwt.bind (Lwt_process.exec cp) (fun _ ->
       let config = target_connector / "config.ml" in
       File.write config config_cont
       |> function
       | Ok () -> Lwt.return_unit
       | Error msg -> Log.err (fun m -> m "write config.ml: %a" R.pp_msg msg)))
  |> function
  | Ok t -> t
  | Error msg -> Log.err (fun m -> m "create_connector: %a" R.pp_msg msg)


let fill_start_tmpl start path =
  let open Bos.OS in
  let open Rresult in
  let path = Fpath.to_string path in
  File.read start
  >>| Re.replace_string (Re.str "%%PATH%%" |> Re.compile) ~by:path


let start_connector dev =
  let open Bos.OS in
  let open Fpath in
  let open Lwt_result.Infix in
  Lwt.return @@ Dir.user ()
  >>= fun user_path ->
  let connector = user_path / (dir_of_dev dev) in
  let start = user_path / "core-bridge" / "driver" / "start.sh.tmpl" in
  Lwt.return @@ fill_start_tmpl start connector
  >>= fun start ->
  let target_start = connector / "start.sh" in
  Lwt.return @@ File.write target_start start
  >>= fun () ->
  let sh = "sh", [|"sh"; Fpath.to_string target_start|] in
  Lwt_result.return @@ Lwt_process.exec sh


let  monitor v () =
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.(set_level @@ if v then Some Debug else Some Info);

  let stm = Lwt_process.pread_lines command in
  let rec aux () =
    Lwt_stream.get stm >>= function
    | Some l ->
        (match if_up l with
        | None ->
            aux ()
        | Some (dev, addr) ->
            Log.info (fun m -> m "if_up: %s %s" dev addr) >>= fun () ->
            create_connector dev addr >>= fun () ->
            start_connector dev >>= fun _ ->
            aux ())
    | None ->
        Lwt_io.printf "closed!"
  in
  aux ()


open Cmdliner

let verbose =
  let doc = "verbose logging" in
  Arg.(value & flag & info ["v"] ~doc)

let cmd =
  let doc = "databox-bridge driver to start interface connectors" in
  Term.(const monitor $ verbose $ const ()),
  Term.info "connector-driver" ~doc ~man:[]


let () =
  match Term.eval cmd with
  | `Ok t -> Lwt_main.run t
  | _ -> exit 1
