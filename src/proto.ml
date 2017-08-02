open Lwt

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


type connection = Lwt_io.input Lwt_io.channel * Lwt_io.output_channel


module Client = struct

  let connect path endp =
    let fd = Lwt_unix.(socket PF_UNIX SOCK_STREAM 0) in
    let addr = Lwt_unix.ADDR_UNIX path in

    catch (fun () ->
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

  let send (_, oc) buf =
    let len = Cstruct.len buf in
    let hd = Cstruct.create 2 in
    Cstruct.LE.set_uint16 hd 0 len;

    Lwt_io.write oc (Cstruct.to_string hd) >>= fun () ->
    Lwt_io.write oc (Cstruct.to_string buf) >>= fun () ->
    Lwt_io.flush oc

  let recv (ic, _) =
    let hd = Bytes.create 2 in
    Lwt_io.read_into_exactly ic hd 0 2 >>= fun () ->
    let len = Cstruct.LE.get_uint16 (Cstruct.of_bytes hd) 0 in

    let buf = Bytes.create len in
    Lwt_io.read_into_exactly ic buf 0 len >>= fun () ->
    return @@ Cstruct.of_bytes buf

  let disconnect (ic, oc) =
    Lwt_io.close ic >>= fun () ->
    Lwt_io.close oc
end
