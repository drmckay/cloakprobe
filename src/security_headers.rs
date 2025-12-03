use axum::http::{HeaderName, HeaderValue};
use tower_http::set_header::SetResponseHeaderLayer;

type HeaderLayer = SetResponseHeaderLayer<HeaderValue>;

pub fn security_headers_layer() -> (
    HeaderLayer,
    HeaderLayer,
    HeaderLayer,
    HeaderLayer,
    HeaderLayer,
    HeaderLayer,
) {
    let csp = SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'self'; \
             script-src 'self' 'unsafe-inline'; \
             style-src 'self' 'unsafe-inline'; \
             img-src 'self' data:; \
             font-src 'self'; \
             connect-src 'self'; \
             frame-ancestors 'none'",
        ),
    );

    let referrer = SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );

    let xfo = SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );

    let hsts = SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
    );

    let xcto = SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    let perm = SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );

    (csp, referrer, xfo, hsts, xcto, perm)
}
