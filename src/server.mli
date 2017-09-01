module Make (B: Vnetif.BACKEND) : sig

  module Request = Opium_kernel.Rock.Request
  module Response = Opium_kernel.Rock.Response

  type conn = Cohttp_mirage.Server_with_conduit.IO.conn * Cohttp.Connection.t
  type callback = conn -> Cohttp.Request.t -> Cohttp_lwt_body.t -> (Cohttp.Response.t * Cohttp_lwt_body.t) Lwt.t
  type t

  val mac: t -> Macaddr.t

  val default_not_found: callback
  val callback_of_routes: (Cohttp.Code.meth * Opium_kernel.Route.t * Opium_kernel.Rock.Handler.t) list -> callback
  val get: string -> Opium_kernel.Rock.Handler.t -> Cohttp.Code.meth * Opium_kernel.Route.t * Opium_kernel.Rock.Handler.t
  val post: string -> Opium_kernel.Rock.Handler.t -> Cohttp.Code.meth * Opium_kernel.Route.t * Opium_kernel.Rock.Handler.t

  val json_of_body_exn: Request.t -> Ezjsonm.t Lwt.t

  type body = [
    | `Html of string
    | `Json of Ezjsonm.t
    | `Xml of string
    | `String of string ]
  val respond : ?headers:Cohttp.Header.t -> ?code:Cohttp.Code.status_code -> body -> Response.t
  val respond' : ?headers:Cohttp.Header.t -> ?code:Cohttp.Code.status_code -> body -> Response.t Lwt.t

  val make: B.t -> Ipaddr.V4.t -> t Lwt.t
  val start: t -> ?port:int -> ?callback:callback -> unit -> unit Lwt.t
end

