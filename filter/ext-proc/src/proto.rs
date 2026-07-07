// SPDX-License-Identifier: MIT AND Apache-2.0 AND BSD-3-Clause
// Copyright (c) 2024 Praxis Contributors
// Vendored Envoy protos: Apache-2.0 (see NOTICE)
// Vendored Google protos: BSD-3-Clause (see NOTICE)

//! Protobuf and gRPC definitions for the Envoy external processing
//! protocol.
//!
//! Compiled from vendored `.proto` files at build time.

pub(crate) mod envoy {
    pub(crate) mod service {
        pub(crate) mod common {
            #[allow(
                dead_code,
                missing_docs,
                unreachable_pub,
                trivial_casts,
                unused_qualifications,
                clippy::doc_markdown,
                clippy::derive_partial_eq_without_eq,
                clippy::doc_lazy_continuation,
                clippy::enum_variant_names,
                clippy::needless_borrows_for_generic_args,
                clippy::default_trait_access,
                reason = "generated protobuf code"
            )]
            pub mod v3 {
                tonic::include_proto!("envoy.service.common.v3");
            }
        }

        pub(crate) mod ext_proc {
            #[allow(
                dead_code,
                missing_docs,
                unreachable_pub,
                trivial_casts,
                unused_qualifications,
                clippy::doc_markdown,
                clippy::derive_partial_eq_without_eq,
                clippy::doc_lazy_continuation,
                clippy::enum_variant_names,
                clippy::needless_borrows_for_generic_args,
                clippy::default_trait_access,
                reason = "generated protobuf code"
            )]
            pub mod v3 {
                tonic::include_proto!("envoy.service.ext_proc.v3");
            }
        }
    }
}
