These files are copied from https://github.com/googleapis/googleapis/ because the pre-compiled
version of these available from https://github.com/googleapis/api-common-protos as
`com.google.api.grpc:proto-google-common-protos` has gone out of date and I can't tell if there's
an intention on keeping up to date. We require `field_behavior.proto` for
`dev.sigstore:protobuf-specs` and {`annotations.proto`, `field_behavior.proto`, `http.proto`}
for `fulcio.proto`. This change is current required to keep our dependencies up to date. Newer
protobuf tools don't work with the very old `proto-google-common-protos` dependency.

The main issue with including these protos here are that a consumer of `sigstore-java` importing
the same protos from another library might experience some sort of dependency clashing.
