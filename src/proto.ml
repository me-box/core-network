open Lwt.Infix

let proto = Logs.Src.create "proto" ~doc:"Communication Protocol"
module Log = (val Logs_lwt.src_log proto : Logs_lwt.LOG)


type connection = Lwt_io.input Lwt_io.channel * Lwt_io.output_channel


type endpoint = {
  interface: string;
  mac_addr : Macaddr.t;
  ip_addr  : Ipaddr.V4.t;
}


let sizeof_endp = 8 + 6 + 4


let marshal_endp {interface; mac_addr; ip_addr} buf =
  let intf =
    let tmp = Bytes.make 8 '\000' in
    let len = String.length interface in
    Bytes.blit_string interface 0 tmp 0 @@ if len <= 8 then len else 8;
    tmp
  in
  Cstruct.blit_from_bytes intf 0 buf 0 8;
  Cstruct.blit_from_bytes (Bytes.of_string @@ Macaddr.to_bytes mac_addr) 0 buf 8 6;
  Cstruct.blit_from_bytes (Bytes.of_string @@ Ipaddr.V4.to_bytes ip_addr) 0 buf (8 + 6) 4;
  Cstruct.shift buf sizeof_endp


let unmarshal_endp buf =
  let interface =
    let tmp = Cstruct.(to_string @@ sub buf 0 8) in
    try String.(sub tmp 0 @@ index tmp '\000')
    with Not_found -> tmp
  in
  let mac_addr = Macaddr.of_bytes_exn @@ Cstruct.(to_string @@ sub buf 8 6) in
  let ip_addr = Ipaddr.V4.of_bytes_exn @@ Cstruct.(to_string @@ sub buf (8 + 6) 4) in
  {interface; mac_addr; ip_addr}, Cstruct.shift buf sizeof_endp

let endp_to_string {interface; mac_addr; ip_addr} =
  Printf.sprintf "endp %s %s %s" interface (Macaddr.to_string mac_addr) (Ipaddr.V4.to_string ip_addr)

let create_endp interface mac_addr ip_addr = {interface; mac_addr; ip_addr}


let sizeof_pkt = 2

let send_pkt oc buf =
  let len = Cstruct.len buf in
  let hd = Cstruct.create sizeof_pkt in
  Cstruct.LE.set_uint16 hd 0 len;
  Lwt_io.write oc (Cstruct.to_string @@ Cstruct.sub hd 0 2) >>= fun () ->
  Lwt_io.write oc (Cstruct.to_string buf) >>= fun () ->
  Lwt_io.flush oc

let recv_pkt ic =
  let hd = Bytes.create 2 in
  Lwt_io.read_into_exactly ic hd 0 2 >>= fun () ->
  let len = Cstruct.LE.get_uint16 (Cstruct.of_bytes hd) 0 in
  let buf = Bytes.create len in
  Lwt_io.read_into_exactly ic buf 0 len >>= fun () ->
  Lwt.return @@ Cstruct.of_bytes buf


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
        Lwt_result.return (in_ch, out_ch))
      (fun e ->
         Lwt_unix.close fd >>= fun () ->
         let msg = Printf.sprintf "Proto.Client.connect failed: %s" @@ Printexc.to_string e in
         Lwt_result.fail @@ `Msg msg)

  let send (_, oc) buf = send_pkt oc buf

  let recv (ic, _) = recv_pkt ic

  let disconnect (ic, oc) =
    Lwt.catch (fun () ->
        Lwt_io.close ic >>= fun () ->
        Lwt_io.close oc) (function
      | Unix.Unix_error (EBADF,_,_) -> Lwt.return_unit
      | e -> Lwt.fail e)
end


module Server = struct

  let bind path =
    Lwt.catch (fun () ->
        Lwt_unix.unlink path)
      (function
      | Unix.Unix_error(Unix.ENOENT, _, _) -> Lwt.return ()
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
          Lwt.catch (fun () ->
              Lwt.finalize (fun () ->
                  let ic = Lwt_io.(of_fd ~mode:input client_fd) in
                  let oc = Lwt_io.(of_fd ~mode:output client_fd) in

                  let endp_buf = Bytes.create sizeof_endp in
                  Lwt_io.read_into_exactly ic endp_buf 0 sizeof_endp >>= fun () ->
                  let endp, _ = unmarshal_endp @@ Cstruct.of_bytes endp_buf in
                  let () = endp_ptr := Some endp in
                  cb endp (ic, oc)) (fun () -> Lwt_unix.close client_fd))
            (function
            | End_of_file ->
                let endp_info = match !endp_ptr with None -> "" | Some e -> endp_to_string e in
                Log.info (fun m -> m "client %s closes connection!" endp_info)
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


  let send (_, oc) buf = send_pkt oc buf

  let recv (ic, _) = recv_pkt ic
end
