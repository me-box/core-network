open Lwt.Infix
open Mirage_types_lwt

let red fmt    = Printf.sprintf ("\027[31m"^^fmt^^"\027[m")
let green fmt  = Printf.sprintf ("\027[32m"^^fmt^^"\027[m")
let yellow fmt = Printf.sprintf ("\027[33m"^^fmt^^"\027[m")
let blue fmt   = Printf.sprintf ("\027[36m"^^fmt^^"\027[m")

module Main (C:CONSOLE)
    (N0: NETWORK) (E0: ETHIF)
    (N1: NETWORK) (E1: ETHIF) = struct


  let start c n0 e0 n1 e1 =
    let t0 = N0.listen n0
        (E0.input
           ~arpv4:(fun _ -> C.log c (red "0 ARP4"))
           ~ipv4:(fun _ -> C.log c (red "0 IPv4"))
           ~ipv6:(fun _ -> C.log c (red "0 IPv6"))
           e0) >>= function
      | Result.Ok () -> C.log c (green "done!")
      | Result.Error _ -> C.log c (red "ping failed!")
    in
    let t1 = N1.listen n1
        (E1.input
           ~arpv4:(fun _ -> C.log c (red "1 ARP4"))
           ~ipv4:(fun _ -> C.log c (red "1 IPv4"))
           ~ipv6:(fun _ -> C.log c (red "1 IPv6"))
           e1) >>= function
      | Result.Ok () -> C.log c (green "done!")
      | Result.Error _ -> C.log c (red "ping failed!")
    in
    Lwt.join [t0; t1]
end
