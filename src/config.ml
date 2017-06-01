open Mirage

let main =
  foreign
    "Unikernel.Main" (console @->
                      network @-> ethernet @->
                      network @-> ethernet @-> job)

let net0 = netif "eth1"
let ethif0 = etif net0

let net1 = netif "eth2"
let ethif1 = etif net1

let () =
  register "ping" [ main $ default_console $ net0 $ ethif0 $ net1 $ ethif1 ]
