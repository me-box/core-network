let secrets_dir = Fpath.v "/run/secrets/"

let cm_key = ref ""

let cm_key () =
  if !cm_key <> "" then Rresult.R.ok !cm_key
  else begin
    let key_file = Fpath.add_seg secrets_dir "CM_KEY" in
    let decode file = B64.decode (String.trim file) in
    Rresult.R.map decode (Bos.OS.File.read key_file)
    |> function
    | Ok key ->
        cm_key := key;
        Rresult.R.ok key
    | Error msg ->
        Logs.err (fun m -> m "[env] CM_KEY %a" Rresult.R.pp_msg msg);
        Error msg
  end

let https_creds () =
  let cert_file  = Fpath.add_seg secrets_dir "DATABOX_BRIDGE.pem" in
  let key_file   = Fpath.add_seg secrets_dir "DATABOX_BRIDGE.pem" in
  Rresult.R.ok (cert_file, key_file)
