open Lwt

module R = Rresult.R

let print_frame buf =
  R.map (fun (t, _) -> Format.printf "%a" Ethif_packet.pp t)
    (Ethif_packet.Unmarshal.of_cstruct buf)
  |> function
  | Ok () -> return_unit
  | Error msg -> Lwt_io.printf "unmarshal error: %s\n%!" msg


let main () =
  let if0 = Sys.argv.(1) in
  Netif.connect if0 >>= fun netif0 ->

  Netif.listen netif0 print_frame >>= fun r0 ->

  let t, _ = Lwt.wait () in

  if R.is_ok r0 then t
  else Lwt_io.printf "listen error!\n%!"


let () = Lwt_main.run @@ main ()
