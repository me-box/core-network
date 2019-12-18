let secrets_dir = Fpath.v "/run/secrets/"

let cm_key = ref ""

let cm_key () =
  if !cm_key <> "" then Rresult.R.ok !cm_key
  else
    let key_file = Fpath.add_seg secrets_dir "DATABOX_NETWORK_KEY" in
    let get_key file = Base64.encode (String.trim file) in
    Rresult.R.map get_key (Bos.OS.File.read key_file)
    |> function
    | Ok key ->
        cm_key := key ;
        Rresult.R.ok key
    | Error msg ->
        Logs.err (fun m ->
            m "[env] DATABOX_NETWORK_KEY %a" Rresult.R.pp_msg msg) ;
        Error msg

let https_creds () =
  let cert_file = Fpath.add_seg secrets_dir "DATABOX_NETWORK.pem" in
  let key_file = Fpath.add_seg secrets_dir "DATABOX_NETWORK.pem" in
  Rresult.R.ok (cert_file, key_file)
