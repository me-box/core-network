open Lwt.Infix

let service = Logs.Src.create "service" ~doc:"REST service of Bridge"

module Log = (val Logs_lwt.src_log service : Logs_lwt.LOG)

module Make (Backend : Vnetif.BACKEND) = struct
  module Vnet = Vnetif.Make (Backend)
  module E = Ethernet.Make (Vnet)
  module A = Arp.Make (E) (OS.Time)
  module I = Static_ipv4.Make (Mirage_random_stdlib) (Mclock) (E) (A)
  module Icmp = Icmpv4.Make (I)
  module U = Udp.Make (I) (Mirage_random_stdlib)
  module T = Tcp.Flow.Make (I) (OS.Time) (Mclock) (Mirage_random_stdlib)
  module Tcpip =
    Tcpip_stack_direct.Make (OS.Time) (Mirage_random_stdlib) (Vnet) (E) (A) (I)
      (Icmp)
      (U)
      (T)
  module C = Conduit_mirage.With_tcp (Tcpip)
  module Http = Cohttp_mirage.Server_with_conduit
  module Request = Opium_kernel.Rock.Request
  module Response = Opium_kernel.Rock.Response

  type conn = Cohttp_mirage.Server_with_conduit.IO.conn * Cohttp.Connection.t

  type callback =
       conn
    -> Cohttp.Request.t
    -> Cohttp_lwt.Body.t
    -> (Cohttp.Response.t * Cohttp_lwt.Body.t) Lwt.t

  type t = {net: Vnet.t; start_fn: Conduit_mirage.server -> Http.t -> unit Lwt.t}

  let or_fail name m =
    Lwt.catch
      (fun () -> m)
      (fun e ->
        Log.err (fun m -> m "%s failed: %s" name @@ Printexc.to_string e)
        >>= fun () -> Lwt.fail e)

  let default_not_found _ req _ =
    let uri = Cohttp.Request.uri req in
    Http.respond_not_found ~uri ()

  let mac {net; _} = Vnet.mac net

  let get route action = (`GET, Opium_kernel.Route.of_string route, action)

  let post route action = (`POST, Opium_kernel.Route.of_string route, action)

  type body =
    [`Html of string | `Json of Ezjsonm.t | `Xml of string | `String of string]

  let content_type ct h = Cohttp.Header.add_opt h "Content-Type" ct

  let json_header = content_type "application/json"

  let xml_header = content_type "application/xml"

  let html_header = content_type "text/html"

  let respond_with_string = Response.of_string_body

  let respond ?headers ?(code = `OK) = function
    | `String s ->
        respond_with_string ?headers ~code s
    | `Json s ->
        respond_with_string ~code ~headers:(json_header headers)
          (Ezjsonm.to_string s)
    | `Html s ->
        respond_with_string ~code ~headers:(html_header headers) s
    | `Xml s ->
        respond_with_string ~code ~headers:(xml_header headers) s

  let respond' ?headers ?code s = s |> respond ?headers ?code |> Lwt.return

  let json_of_body_exn req =
    req |> Request.body |> Cohttp_lwt.Body.to_string >|= Ezjsonm.from_string

  let auth_middleware =
    let name = "check auth for CM" in
    let filter handler req =
      let headers = Request.headers req in
      let open Rresult.R in
      ( match Cohttp.Header.get headers "x-api-key" with
      | Some m ->
          ok m
      | None -> (
        match Cohttp.Header.get_authorization headers with
        | Some (`Basic (name, _)) ->
            ok name
        | _ ->
            error_msg "Missing API key/token" ) )
      >>= (fun key ->
            Env.cm_key ()
            >>= fun key' ->
            if key = key' then ok ()
            else error_msg "Unauthorized: CM key invalid")
      |> function
      | Ok () ->
          Lwt.bind
            (Log.info (fun m -> m "pass CM authentication!"))
            (fun () -> handler req)
      | Error (`Msg msg) ->
          respond' ~code:(`Code 401) (`String msg)
    in
    Opium_kernel.Rock.Middleware.create ~name ~filter

  let callback_of_routes routes =
    let open Opium_kernel in
    let open Rock in
    let router = Router.create () in
    List.iter
      (fun (meth, route, action) -> Router.add ~meth ~route ~action router)
      routes ;
    let m = Router.m router in
    let init = Handler.not_found in
    let filters = List.map Middleware.filter [m; auth_middleware] in
    let handler = Filter.apply_all filters init in
    fun (_ : Http.conn) req body ->
      let req = Request.create ~body req in
      Lwt.catch
        (fun () -> handler req)
        (fun e ->
          Log.err (fun m -> m "handler err: %s" (Printexc.to_string e))
          >>= fun () ->
          let body = Printexc.to_string e in
          let resp = Response.of_string_body ~code:(`Code 500) body in
          Lwt.return resp)
      >>= fun {Response.code; headers; body; _} ->
      Http.respond ~headers ~body ~status:code ()

  let make b ip =
    or_fail "Vnetif.connect" @@ Vnet.connect b
    >>= fun net ->
    or_fail "E.connect" @@ E.connect net
    >>= fun ethif ->
    Mclock.connect ()
    >>= fun clock ->
    or_fail "A.connect" @@ A.connect ethif
    >>= fun arp ->
    or_fail "I.connect" @@ I.connect ~ip () ethif arp
    >>= fun i ->
    or_fail "Random.initialise" @@ Mirage_random_stdlib.initialize ()
    >>= fun () ->
    or_fail "Icmp.connect" @@ Icmp.connect i
    >>= fun icmp ->
    or_fail "U.connect" @@ U.connect i
    >>= fun u ->
    or_fail "T.connect" @@ T.connect i clock
    >>= fun t ->
    or_fail "Tcpip.connect" @@ Tcpip.connect net ethif arp i icmp u t
    >>= fun tcpip ->
    Nocrypto_entropy_lwt.initialize ()
    >>= fun () ->
    or_fail "C.connect" @@ C.connect tcpip Conduit_mirage.empty
    >>= fun c ->
    or_fail "C.with_tls" @@ Conduit_mirage.with_tls c
    >>= fun c_tls ->
    or_fail "Http.connect" @@ Http.connect c_tls
    >>= fun start_fn -> Lwt.return {net; start_fn}

  let server port =
    match Env.https_creds () with
    | Ok (cp, kp) ->
        let cert, priv_key = (Fpath.to_string cp, Fpath.to_string kp) in
        Lwt.catch
          (fun () ->
            X509_lwt.private_of_pems ~cert ~priv_key
            >>= fun certificate ->
            let config =
              Tls.Config.server ~certificates:(`Single certificate) ()
            in
            Lwt.return @@ `TLS (config, `TCP port))
          (fun err ->
            Log.warn (fun m ->
                m "while initializing tls: %s, roll with http"
                  (Printexc.to_string err))
            >>= fun () -> Lwt.return (`TCP port))
    | Error _ ->
        Lwt.return (`TCP port)

  let start {start_fn; _} ?(port = 8080) ?(callback = default_not_found) () =
    server port
    >>= fun server ->
    let t = Http.make ~callback () in
    start_fn server t
end
