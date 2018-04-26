open Lwt.Infix

module Ethif = Ethif.Make(Netif)
module Arpv4 = Arpv4.Make(Ethif)(Mclock)(OS.Time)

let intf = Logs.Src.create "intf" ~doc:"Network Interface"
module Log = (val Logs_lwt.src_log intf : Logs_lwt.LOG)

module Pkt = struct
  let dst_of_ipv4 buf =
    Ipv4_wire.get_ipv4_dst buf
    |> Ipaddr.V4.of_int32

  let eth_hd source destination ethertype =
    Ethif_packet.(Marshal.make_cstruct {source; destination; ethertype})
end


type t = {
  dev : string;
  ip: Ipaddr.V4.t;
  network: Ipaddr.V4.Prefix.t;
  mtu: int;
  mutable gateway: Ipaddr.V4.t option;

  recv_st: Cstruct.t Lwt_stream.t;
  send_push: Cstruct.t option -> unit;
  acquire_fake_ip: unit -> Ipaddr.V4.t Lwt.t;
  release_fake_ip: Ipaddr.V4.t -> unit Lwt.t;
  fake_ips: unit -> Ipaddr.V4.t list;
}


let drop_pkt (_: Cstruct.t) = Lwt.return_unit

let read_intf dev net eth arp recv_push =
  let ipv6 = drop_pkt in
  let ipv4 buf =
    recv_push @@ Some buf;
    Lwt.return_unit in
  let arpv4 = Arpv4.input arp in
  let listen_fn = Ethif.input ~arpv4 ~ipv4 ~ipv6 eth in
  Netif.listen net listen_fn >>= function
  | Ok () -> Log.info (fun m -> m "%s disconnected!" dev)
  | Error e ->
      Log.warn (fun m -> m "%s listen err: %a" dev Netif.pp_error e) >>= fun () ->
      Netif.disconnect net >>= fun () ->
      Lwt.return @@ recv_push None

let rec write_intf t eth arp send_st =
  Lwt_stream.get send_st >>= function
  | Some ipv4_pkt ->
      let src_mac = Ethif.mac eth in
      let dst = Pkt.dst_of_ipv4 ipv4_pkt in
      if not (Ipaddr.V4.Prefix.mem dst t.network) && t.gateway = None then
        Log.err (fun m -> m "%s(%a without gateway) nowhere to send pkt with dst:%a"
            t.dev Ipaddr.V4.Prefix.pp_hum t.network Ipaddr.V4.pp_hum dst) >>= fun () ->
        write_intf t eth arp send_st
      else if dst = Ipaddr.V4.Prefix.broadcast t.network then
        let dst_mac = Macaddr.broadcast in
        let hd = Pkt.eth_hd src_mac dst_mac Ethif_wire.IPv4 in
        Ethif.writev eth [hd; ipv4_pkt] >>= (function
          | Ok () -> Lwt.return_unit
          | Error e -> Log.err (fun m -> m "%s Ethif.writev %a" t.dev Ethif.pp_error e))
        >>= fun () -> write_intf t eth arp send_st
      else
        let query_ip =
          if Ipaddr.V4.Prefix.mem dst t.network then dst
          else match t.gateway with None -> assert false | Some gw -> gw in
        Arpv4.query arp query_ip >>= (function
        | Ok dst_mac ->
            let hd = Pkt.eth_hd src_mac dst_mac Ethif_wire.IPv4 in
            Ethif.writev eth [hd; ipv4_pkt] >>= (function
              | Ok () -> Lwt.return_unit
              | Error e -> Log.err (fun m -> m "%s Ethif.writev %a" t.dev Ethif.pp_error e))
        | Error e ->
            Log.err (fun m -> m "%s Arpv4.query: %a" t.dev Arpv4.pp_error e))
        >>= fun () -> write_intf t eth arp send_st
  | None -> Log.warn (fun m -> m "%s send stream is closed!" t.dev)


let start_intf t net eth arp recv_push send_st () =
  Lwt.catch (fun () ->
      try
        Lwt.pick [
          read_intf t.dev net eth arp recv_push;
          write_intf t eth arp send_st]
      with e -> Lwt.fail e)
    (fun e -> Log.err (fun m -> m "%s on_intf: %s" t.dev (Printexc.to_string e)))


let init_stack dev ip =
  Netif.connect dev >>= fun net ->
  Mclock.connect () >>= fun mclock ->
  let mtu = Netif.mtu net in
  Ethif.connect ~mtu net >>= fun ethif ->
  Arpv4.connect ethif mclock >>= fun arp ->
  Arpv4.set_ips arp [ip] >>= fun () ->
  Lwt.return (net, ethif, arp)


let lt_remove e = List.filter (fun e' -> e' <> e)

let fake_ip_op arp ip network =
  let netmask = Ipaddr.V4.Prefix.bits network in
  let last_added =
    let network = Ipaddr.V4.Prefix.network network in
    let net = Ipaddr.V4.to_int32 network in
    ref (Int32.(add net (shift_left one (32 - netmask) |> pred))) in
  let returned = ref [] in
  (fun () ->
     let fake_ip =
       if 0 <> List.length !returned then
         let next = List.hd !returned in
         returned := List.tl !returned;
         next
       else
         let next = Int32.(sub !last_added one) in
         last_added := next;
         Ipaddr.V4.of_int32 next in
     Arpv4.add_ip arp fake_ip >>= fun () ->
     Lwt.return fake_ip),
  (fun returned_ip ->
     returned := returned_ip :: !returned;
     let ips = Arpv4.get_ips arp in
     let ips' = lt_remove returned_ip ips in
     Arpv4.set_ips arp ips' >>= fun () ->
     Lwt.return_unit)

type starter = unit -> unit Lwt.t

let create ~dev ~cidr =
  let network, ip = Ipaddr.V4.Prefix.of_address_string_exn cidr in
  init_stack dev ip >>= fun (net, eth, arp) ->
  let mtu = Netif.mtu net in
  let recv_st, recv_push = Lwt_stream.create () in
  let send_st, send_push = Lwt_stream.create () in
  let acquire_fake_ip, release_fake_ip = fake_ip_op arp ip network in
  let fake_ips () = Arpv4.get_ips arp |> lt_remove ip in
  let t = {
    dev; ip; network; gateway = None; mtu;
    recv_st; send_push;
    acquire_fake_ip; release_fake_ip; fake_ips} in
  Lwt.return (t, start_intf t net eth arp recv_push send_st)

let set_gateway t gw = t.gateway <- Some gw