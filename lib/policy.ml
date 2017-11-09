open Lwt.Infix
open Utils.Containers

let policy = Logs.Src.create "policy" ~doc:"Junction Policy"
module Log = (val Logs_lwt.src_log policy : Logs_lwt.LOG)


module DomainPairSet = Set.Make(struct
    type t = string * string
    let compare (xx, xy) (yx, yy) =
      if (xx = yx && xy = yy) || (xx = yy && xy = yx) then 0
      else Pervasives.compare (xx, xy) (yx, yy)
  end)


type t = {
  mutable pairs : DomainPairSet.t;
  mutable privileged: IpSet.t;
  mutable transport: IpPairSet.t;
  mutable resolve: (string * Ipaddr.V4.t) list IpMap.t;
  interfaces: Interfaces.t;
  nat: Nat.t;
}

let pp_ip = Ipaddr.V4.pp_hum

let get_related_peers t n =
  DomainPairSet.fold (fun (nx, ny) acc ->
      if nx = n then ny :: acc
      else if ny = n then nx :: acc
      else acc) t.pairs []
  |> Lwt.return

let add_pair t nx ny =
  t.pairs <- DomainPairSet.add (nx, ny) t.pairs;
  Lwt.return_unit

let remove_pair t nx ny =
  t.pairs <- DomainPairSet.remove (nx, ny) t.pairs;
  Lwt.return_unit


let get_resolve t src_ip =
  if IpMap.mem src_ip t.resolve then Lwt.return @@ IpMap.find src_ip t.resolve
  else Lwt.return_nil

let allow_resolve t src_ip name dst_ip =
  if IpMap.mem src_ip t.resolve
  then
    let names = IpMap.find src_ip t.resolve in
    let names' = (name, dst_ip) :: (List.remove_assoc name names) in
    t.resolve <- IpMap.add src_ip names' t.resolve
  else t.resolve <- IpMap.add src_ip [name, dst_ip] t.resolve;
  Log.info (fun m -> m "allow %a to resolve %s (as %a)" pp_ip src_ip name pp_ip dst_ip)

let forbidden_resolve t src_ip name =
  if IpMap.mem src_ip t.resolve
  then
    let names = IpMap.find src_ip t.resolve in
    let names' = List.remove_assoc name names in
    t.resolve <- IpMap.add src_ip names' t.resolve
  else ();
  Log.info (fun m -> m "forbidden %a to resolve %s" pp_ip src_ip name)


let allow_transport t src_ip dst_ip =
  t.transport <- IpPairSet.add (src_ip, dst_ip) t.transport;
  Log.info (fun m -> m "add transport %a -> %a" pp_ip src_ip pp_ip dst_ip)
  >>= fun () -> Lwt.return_unit

let forbidden_transport t src_ip dst_ip =
  t.transport <- IpPairSet.remove (src_ip, dst_ip) t.transport;
  Log.info (fun m -> m "removetransport %a -> %a" pp_ip src_ip pp_ip dst_ip)
  >>= fun () -> Lwt.return_unit


let process_pair_connection t nx ny =
  if DomainPairSet.mem (nx, ny) t.pairs then Lwt.return_unit else
  Lwt_list.map_s Dns_service.ip_of_name [nx; ny] >>= fun ips ->
  let ipx = List.hd ips
  and ipy = List.hd @@ List.tl ips in
  Interfaces.from_same_network t.interfaces ipx ipy >>= function
  | false ->
      add_pair t nx ny >>= fun () ->
      (* dns request from ipx for ny should return ipy' *)
      (* dns request from ipy for nx should return ipx' *)
      Interfaces.acquire_fake_dst t.interfaces ipx >>= fun ipy' ->
      Interfaces.acquire_fake_dst t.interfaces ipy >>= fun ipx' ->
      allow_resolve t ipx ny ipy' >>= fun () ->
      allow_resolve t ipy nx ipx' >>= fun () ->
      (* NAT: ipx -> ipy' => ipx' -> ipy *)
      (* NAT: ipy -> ipx' => ipy' -> ipx *)
      allow_transport t ipx ipy' >>= fun () ->
      allow_transport t ipy ipx' >>= fun () ->
      Nat.add_rule t.nat (ipx, ipy') (ipx', ipy) >>= fun () ->
      Nat.add_rule t.nat (ipy, ipx') (ipy', ipx) >>= fun () ->
      Lwt.return_unit
  | true ->
      (* nx ny are in the same network *)
      (* DNS returns true IP directly, no NAT, no transport *)
      allow_resolve t ipx ny ipy >>= fun () ->
      allow_resolve t ipy nx ipx >>= fun () ->
      Lwt.return_unit


let connect t nx ny =
  Lwt.async (fun () ->
      process_pair_connection t nx ny >>= fun () ->
      Log.info (fun m -> m "Policy.connect %s <> %s" nx ny));
  Lwt.return_unit

let disconnect t n ip =
  get_resolve t ip >>= fun resolve ->
  Lwt_list.iter_p (fun (name, _) -> forbidden_resolve t ip name) resolve >>= fun () ->
  get_related_peers t n >>= fun peers ->
  Lwt_list.iter_p (fun peer -> remove_pair t n peer) peers >>= fun () ->
  Nat.get_rule_handles t.nat ip >>= fun handles ->
  Lwt_list.iter_p (fun handle ->
      let translation = Nat.get_translation t.nat handle in
      let src, dst = handle in
      forbidden_transport t src dst >>= fun () ->
      Interfaces.release_fake_dst t.interfaces dst >>= fun () ->
      Nat.remove_rule t.nat handle >>= fun () ->
      if List.length translation <> 0 then
        let dst', src' = List.hd translation in
        forbidden_transport t src' dst' >>= fun () ->
        Interfaces.release_fake_dst t.interfaces dst' >>= fun () ->
        Nat.remove_rule t.nat (src', dst')
      else Lwt.return_unit) handles >>= fun () ->
  Log.info (fun m -> m "Policy.disconnect %s" n)


let allow_privileged t src_ip =
  t.privileged <- IpSet.add src_ip t.privileged;
  Log.info (fun m -> m "allow privileged: %a" pp_ip src_ip)


let is_authorized_transport {transport; _} ipx ipy =
  IpPairSet.mem (ipx, ipy) transport


let is_privileged_resolve t src_ip name =
  if IpSet.mem src_ip t.privileged then
    Dns_service.ip_of_name name >>= fun dst_ip ->
    Interfaces.from_same_network t.interfaces src_ip dst_ip >>= function
    | true ->
        allow_resolve t src_ip name dst_ip >>= fun () ->
        Lwt.return (Ok (src_ip, dst_ip))
    | false ->
        Interfaces.acquire_fake_dst t.interfaces src_ip >>= fun dst_ip' ->
        Interfaces.acquire_fake_dst t.interfaces dst_ip >>= fun src_ip' ->
        allow_resolve t src_ip name dst_ip' >>= fun () ->
        allow_transport t src_ip dst_ip' >>= fun () ->
        allow_transport t dst_ip src_ip' >>= fun () ->
        Nat.add_rule t.nat (src_ip, dst_ip') (src_ip', dst_ip) >>= fun () ->
        Nat.add_rule t.nat (dst_ip, src_ip') (dst_ip', src_ip) >>= fun () ->
        Lwt.return (Ok (src_ip, dst_ip'))
  else Lwt.return (Error src_ip)


let is_authorized_resolve t ip name =
  if IpMap.mem ip t.resolve then
    let names = IpMap.find ip t.resolve in
    if List.mem_assoc name names then Lwt.return @@ Ok (ip, List.assoc name names)
    else is_privileged_resolve t ip name
  else is_privileged_resolve t ip name


let create interfaces nat =
  let pairs = DomainPairSet.empty in
  let privileged = IpSet.empty in
  let transport = IpPairSet.empty in
  let resolve = IpMap.empty in
  {pairs; privileged; transport; resolve; interfaces; nat}
