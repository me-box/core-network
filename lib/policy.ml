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

type privileged = SrcIP of Ipaddr.V4.t | DstHost of string | Network of Ipaddr.V4.Prefix.t
module PrivilegedSet = Set.Make(struct
  type t = privileged
  let compare x y = match x, y with
    | SrcIP a, SrcIP b -> Ipaddr.V4.compare a b
    | DstHost a, DstHost b -> Pervasives.compare a b
    | Network a, Network b -> Ipaddr.V4.Prefix.compare a b
    | _, _ -> 1
end)

type t = {
  mutable pairs : DomainPairSet.t;
  mutable privileged: PrivilegedSet.t;
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
  Log.info (fun m -> m "remove transport %a -> %a" pp_ip src_ip pp_ip dst_ip)
  >>= fun () -> Lwt.return_unit


let process_pair_connection t nx ny =
  if DomainPairSet.mem (nx, ny) t.pairs then Lwt.return_unit
  else
    add_pair t nx ny >>= fun () ->
    if List.exists (fun e -> PrivilegedSet.mem e t.privileged) [DstHost nx; DstHost ny]
    then Log.info (fun m -> m "Policy.connect skip privileged hostname %s|%s" nx ny)
    else
      Lwt_list.map_p Dns_service.ip_of_name [nx; ny] >>= fun ips ->
      let ipx = List.hd ips
      and ipy = List.hd @@ List.tl ips in
      Interfaces.from_same_network t.interfaces ipx ipy >>= function
      | false ->
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
          Log.info (fun m -> m "Policy.connect %s <> %s" nx ny)
      | true ->
          (* nx ny are in the same network *)
          (* DNS returns true IP directly, no NAT, no transport *)
          allow_resolve t ipx ny ipy >>= fun () ->
          allow_resolve t ipy nx ipx >>= fun () ->
          Log.info (fun m -> m "Policy.connect %s <> %s" nx ny)


let connect t nx ny =
  Lwt.async (fun () ->
    Lwt.catch (fun () -> process_pair_connection t nx ny)
      (function
      | Invalid_argument n ->
          Log.err (fun m -> m "Policy.connect unresolvable %s" n)
      | exn -> Lwt.fail exn));
  Lwt.return_unit

let disconnect t n ip =
  (* service n can't resolve others *)
  get_resolve t ip >>= fun resolve ->
  Lwt_list.iter_s (fun (name, _) -> forbidden_resolve t ip name) resolve >>= fun () ->
  (* others can't resolve n *)
  Lwt_list.iter_s (fun (ip, resolves) ->
    if not (List.mem_assoc n resolves) then Lwt.return_unit
    else forbidden_resolve t ip n) (IpMap.bindings t.resolve) >>= fun () ->
  get_related_peers t n >>= fun peers ->
  Lwt_list.iter_s (fun peer -> remove_pair t n peer) peers >>= fun () ->
  Nat.get_rule_handles t.nat ip >>= fun handles ->
  Lwt_list.iter_s (fun handle ->
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


let allow_privileged_ip t src_ip =
  t.privileged <- PrivilegedSet.add (SrcIP src_ip) t.privileged;
  Log.info (fun m -> m "allow privileged IP: %a" pp_ip src_ip)

let allow_privileged_host t name =
  t.privileged <- PrivilegedSet.add (DstHost name) t.privileged;
  Log.info (fun m -> m "allow privileged hostname: %s" name)

let allow_privileged_network t net =
  t.privileged <- PrivilegedSet.add (Network net) t.privileged;
  Log.info (fun m -> m "allow privileged network: %a" Ipaddr.V4.Prefix.pp_hum net)

let disallow_privileged_network t net =
  t.privileged <- PrivilegedSet.remove (Network net) t.privileged;
  Log.info (fun m -> m "disallow privileged network: %a" Ipaddr.V4.Prefix.pp_hum net)

let is_authorized_transport {transport; _} ipx ipy =
  IpPairSet.mem (ipx, ipy) transport

(* difference with pair_connection: name resolving is unidirectional, *)
(* `allow_resolve` only called once here *)
let connect_for_privileged_exn t src_ip name =
  Log.info (fun m -> m "Policy.connect_for_privileged %a <> %s" pp_ip src_ip name) >>= fun () ->
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

let connect_for_privileged t src_ip name =
  Lwt.catch (fun () -> connect_for_privileged_exn t src_ip name) (function
    | Invalid_argument n ->
        Log.err (fun m -> m "Policy.connect_for_privileged unresolvable %s" n) >>= fun () ->
        Lwt.return @@ Error src_ip
    | exn -> Lwt.fail exn)

let is_from_privileged_net t ip =
  PrivilegedSet.exists (function
      | Network net -> Ipaddr.V4.Prefix.mem ip net
      | _ -> false) t.privileged

let is_authorized_resolve t ip name =
  if IpMap.mem ip t.resolve && List.mem_assoc name @@ IpMap.find ip t.resolve then
    Lwt.return @@ Ok (ip, List.assoc name @@ IpMap.find ip t.resolve)
  else if PrivilegedSet.mem (SrcIP ip) t.privileged ||
          PrivilegedSet.mem (DstHost name) t.privileged ||
          is_from_privileged_net t ip then
    connect_for_privileged t ip name
  else Lwt.return @@ Error ip


(*
* type t = {
*   mutable pairs : DomainPairSet.t;
*   mutable privileged: PrivilegedSet.t;
*   mutable transport: IpPairSet.t;
*   mutable resolve: (string * Ipaddr.V4.t) list IpMap.t;
*   interfaces: Interfaces.t;
*   nat: Nat.t;
* }
*)
let substitute t name old_ip new_ip =
  Log.info (fun m -> m "Policy.substititue %a for %a" pp_ip old_ip pp_ip new_ip) >>= fun () ->
  if PrivilegedSet.mem (SrcIP old_ip) t.privileged then begin
    PrivilegedSet.remove (SrcIP old_ip) t.privileged
    |> PrivilegedSet.add (SrcIP new_ip)
    |> fun npriv -> t.privileged <- t.privileged end;

  let ntransp =
    IpPairSet.fold (fun (_src_ip, _dst_ip) n ->
      (if 0 = Ipaddr.V4.compare _src_ip old_ip then new_ip, _dst_ip
      else if 0 = Ipaddr.V4.compare _dst_ip old_ip then _src_ip, new_ip
      else _src_ip, _dst_ip)
      |> fun np -> IpPairSet.add np n
    ) t.transport IpPairSet.empty in
  let () = t.transport <- ntransp in

  let nresolv =
    IpMap.fold (fun src_ip resolvs n ->
      List.map (fun (_name, _dst_ip) ->
        if 0 = Ipaddr.V4.compare _dst_ip old_ip then _name, new_ip
        else _name, _dst_ip) resolvs
      |> fun nresolvs ->
        if 0 = Ipaddr.V4.compare src_ip old_ip then IpMap.add new_ip nresolvs n
        else IpMap.add src_ip nresolvs n
    ) t.resolve IpMap.empty in
  let () = t.resolve <- nresolv in

  Interfaces.substitute t.interfaces old_ip new_ip >>= fun () ->
  Nat.substitute t.nat old_ip new_ip >>= fun () ->
  Lwt.return_unit


let create interfaces nat =
  let pairs = DomainPairSet.empty in
  let privileged = PrivilegedSet.empty in
  let transport = IpPairSet.empty in
  let resolve = IpMap.empty in
  {pairs; privileged; transport; resolve; interfaces; nat}
