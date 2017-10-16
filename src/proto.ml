open Lwt.Infix

let proto = Logs.Src.create "proto" ~doc:"Communication Protocol"
module Log = (val Logs_lwt.src_log proto : Logs_lwt.LOG)


type connection = Lwt_io.input Lwt_io.channel * Lwt_io.output_channel


type endpoint = {
  interface: string;
  mac_addr : Macaddr.t;
  mtu      : Cstruct.uint16;
  ip_addr  : Ipaddr.V4.t;
  netmask  : Cstruct.uint16;
}


let sizeof_endp = 8 + 6 + 2 + 4 + 2


let marshal_endp {interface; mac_addr; mtu; ip_addr; netmask} buf =
  let intf =
    let tmp = Bytes.make 8 '\000' in
    let len = String.length interface in
    Bytes.blit_string interface 0 tmp 0 @@ if len <= 8 then len else 8;
    tmp
  in
  Cstruct.blit_from_bytes intf 0 buf 0 8;
  Cstruct.blit_from_bytes (Bytes.of_string @@ Macaddr.to_bytes mac_addr) 0 buf 8 6;
  Cstruct.BE.set_uint16 buf (8 + 6) mtu;
  Cstruct.blit_from_bytes (Bytes.of_string @@ Ipaddr.V4.to_bytes ip_addr) 0 buf (8 + 6 + 2) 4;
  Cstruct.BE.set_uint16 buf (8 + 6 + 2 + 4) netmask;
  Cstruct.shift buf sizeof_endp


let unmarshal_endp buf =
  let interface =
    let tmp = Cstruct.(to_string @@ sub buf 0 8) in
    try String.(sub tmp 0 @@ index tmp '\000')
    with Not_found -> tmp
  in
  let mac_addr = Macaddr.of_bytes_exn @@ Cstruct.(to_string @@ sub buf 8 6) in
  let mtu = Cstruct.BE.get_uint16 buf (8 + 6) in
  let ip_addr = Ipaddr.V4.of_bytes_exn @@ Cstruct.(to_string @@ sub buf (8 + 6 + 2) 4) in
  let netmask = Cstruct.BE.get_uint16 buf (8 + 6 + 2 + 4) in
  {interface; mac_addr; mtu; ip_addr; netmask}, Cstruct.shift buf sizeof_endp

let endp_to_string {interface; mac_addr; mtu; ip_addr; netmask} =
  Printf.sprintf "endp %s %s %d  %s/%d" interface (Macaddr.to_string mac_addr) mtu (Ipaddr.V4.to_string ip_addr) netmask

let create_endp interface mac_addr mtu ip_addr netmask = {interface; mac_addr; mtu; ip_addr; netmask}


type command =
  | IP_REQ of int32
  | IP_DUP of Ipaddr.V4.t
  | ACK of (Ipaddr.V4.t * int32)

let sizeof_command = 1 + 4 + 4

let marshal_command comm buf =
  assert (Cstruct.len buf >= sizeof_command);
  begin match comm with
  | IP_REQ seq ->
      Cstruct.set_uint8 buf 0 1;
      Cstruct.BE.set_uint32 buf 1 seq
  | IP_DUP dup ->
      Cstruct.set_uint8 buf 0 2;
      Cstruct.blit_from_bytes (Bytes.of_string @@ Ipaddr.V4.to_bytes dup) 0 buf 1 4
  | ACK (ip, seq) ->
      Cstruct.set_uint8 buf 0 4;
      Cstruct.blit_from_bytes (Bytes.of_string @@ Ipaddr.V4.to_bytes ip) 0 buf 1 4;
      Cstruct.BE.set_uint32 buf (1 + 4) seq
  end;
  Cstruct.shift buf sizeof_command

let unmarshal_command buf =
  assert (Cstruct.len buf >= sizeof_command);
  let comm = Cstruct.get_uint8 buf 0 in
  match comm with
  | 1 -> IP_REQ (Cstruct.BE.get_uint32 buf 1)
  | 2 -> IP_DUP (Ipaddr.V4.of_bytes_exn @@ Cstruct.(to_string @@ sub buf 1 4))
  | 4 -> ACK (Ipaddr.V4.of_bytes_exn @@ Cstruct.(to_string @@ sub buf 1 4),
              Cstruct.BE.get_uint32 buf (1 + 4))
  | n -> assert false


let sizeof_hd = 2 + 1 (* len + typ *)

let send typ oc buf =
  let len = Cstruct.len buf in
  let typ =
    match typ with
    | `PKT -> 0
    | `COMM -> 1
    | _ -> assert false
  in
  let hd = Cstruct.create sizeof_hd in
  Cstruct.BE.set_uint16 hd 0 len;
  Cstruct.set_uint8 hd 2 typ;
  Lwt.catch (fun () ->
      Lwt_io.write oc (Cstruct.to_string @@ Cstruct.sub hd 0 sizeof_hd) >>= fun () ->
      Lwt_io.write oc (Cstruct.to_string buf) >>= fun () ->
      Lwt_io.flush oc) (function
    | Unix.(Unix_error (EBADF, _, _)) as exn ->
        Log.err (fun m -> m "EBADF of typ %d len %d" typ len) >>= fun () ->
        Lwt.fail exn
    | exn -> Lwt.fail exn)

let recv ic =
  try
    let hd = Bytes.create sizeof_hd in
    Lwt_io.read_into_exactly ic hd 0 sizeof_hd >>= fun () ->
    let hd = Cstruct.of_bytes hd in
    let len = Cstruct.BE.get_uint16 hd 0 in
    let typ = Cstruct.get_uint8 hd 2 in
    let buf = Bytes.create len in
    Lwt_io.read_into_exactly ic buf 0 len >>= fun () ->
    (match typ with
    | 0 -> `PKT (Cstruct.of_bytes buf)
    | 1 -> `COMM (unmarshal_command (Cstruct.of_bytes buf))
    | _ -> assert false)
    |> Lwt.return
  with exn -> Lwt.fail exn


let split_streams in_ch =
  let pkt_s, push_pkt = Lwt_stream.create () in
  let comm_s, push_comm = Lwt_stream.create () in

  let rec recv_and_push () =
    recv in_ch >>= function
    | `PKT pkt ->
        push_pkt @@ Some pkt;
        recv_and_push ()
    | `COMM comm ->
        push_comm @@ Some comm;
        recv_and_push () in

  let t, close = Lwt.wait () in
  let wait_to_close () =
    t >>= fun () ->
    push_pkt None;
    push_comm None;
    Lwt.return_unit in

  Lwt.async (fun () ->
      Lwt.catch
        (fun () ->
           Lwt.pick [recv_and_push (); wait_to_close ()])
        (fun exn ->
           if Lwt_stream.is_closed pkt_s && Lwt_stream.is_closed comm_s
           then Lwt.return_unit
           else Log.err (fun m -> m "split_streams async err: %s" (Printexc.to_string exn))));
  (pkt_s, comm_s, close)


module Client = struct

  let connect path endp =
    let fd = Lwt_unix.(socket PF_UNIX SOCK_STREAM 0) in
    let addr = Lwt_unix.ADDR_UNIX path in

    Lwt.catch (fun () ->
        Lwt_unix.connect fd addr >>= fun () ->
        let in_ch = Lwt_io.(of_fd ~mode:input fd) in
        let out_ch = Lwt_io.(of_fd ~mode:output fd) in

        let init_fr = Cstruct.create sizeof_endp in
        let (_: Cstruct.t) = marshal_endp endp init_fr in
        Lwt_io.write out_ch (Cstruct.to_string init_fr) >>= fun () ->
        Lwt_io.flush out_ch >>= fun () ->
        let pkt_s, comm_s, close = split_streams in_ch in
        Lwt_result.return (pkt_s, comm_s, out_ch, close))
      (fun e ->
         Lwt_unix.close fd >>= fun () ->
         let msg = Printf.sprintf "Proto.Client.connect failed: %s" @@ Printexc.to_string e in
         Lwt_result.fail @@ `Msg msg)

  let send_pkt (_, _, oc, _) buf = send `PKT oc buf
  let send_comm (_, _, oc, _) comm =
    let buf = Cstruct.create sizeof_command in
    let (_: Cstruct.t) = marshal_command comm buf in
    send `COMM oc buf

  let recv_pkt (pkt_s, _, _, _) = Lwt_stream.next pkt_s
  let recv_comm (_, comm_s, _, _) = Lwt_stream.next comm_s

  let disconnect (_, _, oc, close) =
    Log.warn (fun m -> m "client about to close connection!") >>= fun () ->
    Lwt.catch (fun () ->
        Lwt.wakeup close ();
        Lwt_io.close oc) (function
      | Unix.Unix_error (Unix.EBADF,_,_) -> Lwt.return_unit
      | e -> Lwt.fail e)
end


module Server = struct

  type client_connection = Cstruct.t Lwt_stream.t * command Lwt_stream.t * Lwt_io.output Lwt_io.channel

  let bind path =
    Lwt.catch (fun () ->
        Lwt_unix.unlink path)
      (function
      | Unix.Unix_error (Unix.ENOENT, _, _) -> Lwt.return ()
      | e -> Lwt.fail e)
    >>= fun () ->

    let s = Lwt_unix.(socket PF_UNIX SOCK_STREAM 0) in
    Lwt.catch (fun () ->
        Lwt_unix.(bind s @@ ADDR_UNIX path) >>= fun () ->
        Lwt.return s)
      (fun e ->
         Lwt_unix.close s >>= fun () ->
         Lwt.fail e)

  let listen ?(max=128) fd cb =
    let rec loop_accept fd =
      Lwt_unix.accept fd >>= fun (client_fd, _) ->
      Lwt.async (fun () ->
          let endp_ptr = ref None in
          let close_ptr = ref None in
          Lwt.catch (fun () ->
              Lwt.finalize (fun () ->
                  let ic = Lwt_io.(of_fd ~mode:input client_fd) in
                  let oc = Lwt_io.(of_fd ~mode:output client_fd) in

                  let endp_buf = Bytes.create sizeof_endp in
                  Lwt_io.read_into_exactly ic endp_buf 0 sizeof_endp >>= fun () ->
                  let endp, _ = unmarshal_endp @@ Cstruct.of_bytes endp_buf in
                  let () = endp_ptr := Some endp in

                  let pkt_s, comm_s, close = split_streams ic in
                  let () = close_ptr := Some close in
                  cb endp (pkt_s, comm_s, oc)) (fun () ->
                  Log.warn (fun m -> m "server about to close connection!") >>= (fun () ->
                  match !endp_ptr with
                  | None -> Lwt.return_unit
                  | Some endp ->
                      Log.warn (fun m -> m "client endp to close: %s" (endp_to_string endp))) >>= fun () ->
                  Lwt_unix.close client_fd))
            (function
            | End_of_file | Unix.(Unix_error (EBADF, _, _)) ->
                let endp_info = match !endp_ptr with None -> "" | Some e -> endp_to_string e in
                Log.info (fun m -> m "closed connection from %s" endp_info) >>= fun () ->
                (match !close_ptr with
                | Some close -> Lwt.return @@ Lwt.wakeup close ()
                | None -> Lwt.return_unit)
            | e ->
                Log.err (fun m -> m "Proto.Server.listen accept err: %s" @@ Printexc.to_string e)));
      loop_accept fd
    in

    Lwt.async (fun () ->
        Lwt.catch (fun () ->
            Lwt_unix.listen fd max;
            loop_accept fd)
          (fun e ->
             Log.err (fun m -> m "Proto.Server.listen listen err: %s" @@ Printexc.to_string e)));
    Lwt.return_unit


  let send_pkt (_, _, oc) buf = send `PKT oc buf
  let send_comm (_, _, oc) comm =
    let buf = Cstruct.create sizeof_command in
    let (_: Cstruct.t) = marshal_command comm buf in
    send `COMM oc buf

  let recv_pkt (pkt_s, _, _) = Lwt_stream.next pkt_s
  let recv_comm (_, comm_s, _) = Lwt_stream.next comm_s

end

