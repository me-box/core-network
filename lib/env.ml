let secrets_dir = Fpath.v "/run/secrets/"

let cm_key = ref ""

let on_error f = function Error msg -> f msg ; Error msg | v -> v

let cm_key () =
  let ( let* ) = Rresult.R.bind in
  if !cm_key <> "" then Rresult.R.ok !cm_key
  else
    (let key_file = Fpath.add_seg secrets_dir "DATABOX_NETWORK_KEY" in
     let* file = Bos.OS.File.read key_file in
     let* key = file |> String.trim |> Base64.encode in
     cm_key := key ;
     Rresult.R.ok key)
    |> on_error (fun msg ->
           Logs.err (fun m ->
               m "[env] DATABOX_NETWORK_KEY %a" Rresult.R.pp_msg msg))

let https_creds () =
  let cert_file = Fpath.add_seg secrets_dir "DATABOX_NETWORK.pem" in
  let key_file = Fpath.add_seg secrets_dir "DATABOX_NETWORK.pem" in
  Rresult.R.ok (cert_file, key_file)
