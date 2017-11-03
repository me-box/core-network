open Lwt.Infix

module Log = struct
  type log_threshold = [`All | `Src of string] * Logs.level

  module Log_config = Mirage_logs.Make(Pclock)

  let set_up_logs logs =
    let set_level ~default l =
      let srcs = Logs.Src.list () in
      let default =
        try snd @@ List.find (function (`All, _) -> true | _ -> false) l
        with Not_found -> default
      in
      Logs.set_level (Some default);
      List.iter (function
        | (`All, _) -> ()
        | (`Src src, level) ->
            try
              let s = List.find (fun s -> Logs.Src.name s = src) srcs in
              Logs.Src.set_level s (Some level)
            with Not_found ->
              Fmt.(pf stdout) "%a %s is not a valid log source.\n%!"
                Fmt.(styled `Yellow string) "Warning:" src
        ) l
    in
    Pclock.connect () >>= fun pclock ->
    let reporter = Log_config.create pclock in
    set_level ~default:Logs.Warning logs;
    Log_config.set_reporter reporter;
    Lwt.return_unit


  let log_threshold =
    let enum = [
      "error"  , Logs.Error;
      "warning", Logs.Warning;
      "info"   , Logs.Info;
      "debug"  , Logs.Debug;
    ] in
    let level_of_string x =
      try List.assoc x enum
      with Not_found -> Fmt.kstrf failwith "%s is not a valid log level" x
    in
    let string_of_level x =
      try fst @@ List.find (fun (_, y) -> x = y) enum
      with Not_found -> "warning"
    in
    let parser str =
      match Astring.String.cut ~sep:":" str with
      | None            -> `Ok (`All    , level_of_string str)
      | Some ("*", str) -> `Ok (`All    , level_of_string str)
      | Some (src, str) -> `Ok (`Src src, level_of_string str)
    in
    let serialize ppf = function
    | `All  , l -> Fmt.string ppf (string_of_level l)
    | `Src s, l -> Fmt.pf ppf "%s:%s" s (string_of_level l)
    in
    parser, serialize
  end

module Containers = struct
  type pair = Ipaddr.V4.t * Ipaddr.V4.t

  module IpPairMap = Map.Make(struct
    type t = pair
    let compare (xx, xy) (yx, yy) =
      let open Ipaddr.V4 in
      if compare xx yx = 0 && compare xy yy = 0 then 0
      else if 0 <> compare xx yx then compare xx yx
      else compare xy yy
  end)

  module IpPairSet = Set.Make(struct
    type t = pair
    let compare (xx, xy) (yx, yy) =
      let open Ipaddr.V4 in
      if compare xx yx = 0 && compare xy yy = 0 then 0
      else if 0 <> compare xx yx then compare xx yx
      else compare xy yy
  end)

  module IpMap = Map.Make(struct
      type t = Ipaddr.V4.t
      let compare = Ipaddr.V4.compare
    end)

  module IpSet = Set.Make(struct
    type t = Ipaddr.V4.t
    let compare = Ipaddr.V4.compare
  end)
end