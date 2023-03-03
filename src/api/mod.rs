use macros::router;

router! {
    /auth,
    /health_check,
}

mod macros {
    macro_rules! router {
    (
        $($method:ident,)*
        $(/$segment:ident,)*
        $(/:$param:ident,)*
    ) => {
        $( mod $method; )*
        $( mod $segment; )*
        $( mod $param; )*

        pub fn router() -> ::axum::Router<$crate::server::ServerState> {
            ::axum::Router::new()
            $( .route("/", ::axum::routing::$method($method::handler)) )*
            $( .nest(&format!("/{}", stringify!($segment)), $segment::router()) )*
            $( .nest(&format!("/:{}", stringify!($param)), $param::router()) )*
        }
    };
    }

    pub(super) use router;
}
