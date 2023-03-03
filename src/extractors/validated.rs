macros::validated_extractor! {
    (Form, FormRejection),
    (Json, JsonRejection)
}

mod macros {
    macro_rules! validated_extractor {
        ( $( ($extractor:ident, $rejection:ident) ), * ) => {
            #[derive(
                ::std::clone::Clone,
                ::std::marker::Copy,
                ::std::fmt::Debug,
                ::std::default::Default,
            )]
            $(
            pub struct $extractor<T>(pub T);

            #[async_trait::async_trait]
            impl<T, S, B> ::axum::extract::FromRequest<S, B> for $extractor<T>
            where
                T: ::serde::de::DeserializeOwned + ::validator::Validate,
                S: ::core::marker::Send + ::core::marker::Sync,
                ::axum::extract::$extractor<T>: ::axum::extract::FromRequest<
                    S,
                    B,
                    Rejection = ::axum::extract::rejection::$rejection,
                >,
                B: ::core::marker::Send + 'static,
            {
                type Rejection = $crate::extractors::Error;

                async fn from_request(
                    req: ::axum::http::Request<B>,
                    state: &S,
                ) -> ::std::result::Result<Self, Self::Rejection> {
                    let ::axum::extract::$extractor(value) =
                        ::axum::extract::$extractor::<T>::from_request(req, state).await?;
                    value.validate()?;
                    Ok($extractor(value))
                }
            }
            )*
        };
    }

    pub(super) use validated_extractor;
}
