open Mirage


let net = netif "0"


let main = foreign "Unikernel.Main" (network @-> job)


let () = register "netif" [main $ net]
