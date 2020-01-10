open Lwt.Infix

let bcast = Logs.Src.create "bcast" ~doc:"Broadcast traffic repeater"

module Log = (val Logs_lwt.src_log bcast : Logs_lwt.LOG)

let no_broadcast () = Lwt.return_unit

let open_fifo name = Lwt_unix.openfile name [Unix.O_RDONLY] 0o640

let read_len fd buf len =
  let rec read cnt buf =
    if cnt = len then Lwt.return_unit
    else
      Lwt_cstruct.read fd buf
      >>= fun rlen -> read (cnt + rlen) (Cstruct.shift buf rlen)
  in
  read 0 buf

let extract_bcast_pkt fd hd () =
  Lwt.catch
    (fun () ->
      read_len fd hd 2
      >>= fun () ->
      Lwt.return @@ Cstruct.BE.get_uint16 hd 0
      >>= fun pkt_len ->
      let pkt = Cstruct.create pkt_len in
      read_len fd pkt pkt_len >>= fun () -> Lwt.return_some pkt)
    (fun exn ->
      Log.err (fun m -> m "extract_bcast_pkt %s" (Printexc.to_string exn))
      >>= fun () -> Lwt.return_none)

let create ?fifo interfaces =
  match fifo with
  | None ->
      Lwt.return no_broadcast
  | Some fname ->
      open_fifo fname
      >>= fun fd ->
      let hd = Cstruct.create 2 in
      let pkt_stm = Lwt_stream.from (extract_bcast_pkt fd hd) in
      let rec relay_lp () =
        Lwt_stream.get pkt_stm
        >>= function
        | Some pkt ->
            Log.debug (fun m -> m "got one broadcast pkt: %d" (Cstruct.len pkt))
            >>= fun () ->
            Interfaces.relay_bcast interfaces pkt ;
            relay_lp ()
        | None ->
            Lwt.return_unit
      in
      Lwt.return relay_lp
