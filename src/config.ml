open Mirage

let main =
  foreign
    "Unikernel.Main" (stackv4 @->
                      network @->
                      network @->
                      network @->(* ethernet @-> arpv4 @-> ipv4 @-> udpv4 @->*)
                      job)

let dns_stack = socket_stackv4 [Ipaddr.V4.of_string_exn "127.0.0.1"]

let net1_group = "net1"
let net1 = netif ~group:net1_group "eth1"

(*
let ethif0 = etif net0
let arp0 = arp ethif0
let ip0 =
  let config = {
      network = Ipaddr.V4.Prefix.of_address_string_exn "172.18.0.2/16";
      gateway = None}
  in
  create_ipv4 ~group:net0_group ~config ethif0 arp0
let udp0 = direct_udp ip0
*)

let net2_group = "net2"
let net2 = netif ~group:net2_group "eth2"

(*
let ethif1 = etif net1
let arp1 = arp ethif1
let ip1 =
  let config = {
      network = Ipaddr.V4.Prefix.of_address_string_exn "172.19.0.2/16";
      gateway = None}
  in
  create_ipv4 ~group:net1_group ~config ethif1 arp1
let udp1 = direct_udp ip1
*)


let net3_group = "net3"
let net3 = netif ~group:net3_group "eth3"

(*
let ethif2 = etif net2
let arp2 = arp ethif2
let ip2 =
  let config = {
      network = Ipaddr.V4.Prefix.of_address_string_exn "172.20.0.2/16";
      gateway = None}
  in
  create_ipv4 ~group:net2_group ~config ethif2 arp2
let udp2 = direct_udp ip2
*)


let () =
  let packages = [
    package "uuidm";
    package ~sublibs:["mirage"] "dns";
    package ~sublibs:["lwt"]    "logs";
    package ~sublibs:["icmpv4"] "tcpip";
  ] in
  register ~packages "bridge" [
    main $ dns_stack $
    net1 $
    net2 $
    net3 (*$ ethif2 $ arp2 $ ip2 $ udp2*)
  ]
