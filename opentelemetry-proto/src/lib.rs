//! This crate contains generated files from [opentelemetry-proto](https://github.com/open-telemetry/opentelemetry-proto)
//! repository and transformation between types from generated files and types defined in [opentelemetry](https://github.com/open-telemetry/opentelemetry-rust/tree/main/opentelemetry)
//!
//! Based on the build tool needed, users can choose to generate files using [tonic](https://github.com/hyperium/tonic)
//! or [grpcio](https://github.com/tikv/grpc-rs).
//!
//! # Feature flags
//! `Opentelemetry-proto` includes a set of feature flags to avoid pull in unnecessary dependencies.
//! The following is the full list of currently supported features:
//!
//! - `gen-tonic`: generate rs files using [tonic](https://github.com/hyperium/tonic) and [prost](https://github.com/tokio-rs/prost).
//! - `gen-protoc`: generate rs files using [grpcio](https://github.com/tikv/grpc-rs).
//! - `traces`: generate types that used in traces.
//! - `metrics`: generate types that used in metrics.
//! - `zpages`: generate types that used in zPages. Currently only tracez related types will be generated.
//! - `build-server`: build grpc service servers if enabled. Only applied to `gen-tonic`.
//! - `build-client`: build grpc service clients if enabled. Only applied to `gen-tonic`.
//! - `with-serde`: add serde annotations to generated types. Only applied to `gen-protoc`.
//! - `full`: enabled all features above.
//!
//! By default, no feature is enabled.

// proto mod contains file generated by protobuf or other build tools.
// we should manually change it. Thus skip format and lint check.
#[rustfmt::skip]
#[allow(warnings)]
#[doc(hidden)]
mod proto;

#[cfg(feature = "gen-protoc")]
pub use proto::grpcio;
#[cfg(feature = "gen-tonic")]
pub use proto::tonic;

mod transform;