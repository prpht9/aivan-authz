# The gate's image: a static binary on distroless.
#
# One binary, and it serves only. The operator commands (enroll-new, revoke,
# list-devices, purge, service) are in cmd/authz-admin, which is built on a
# workstation and never copied here. That is the control in
# doc/schema-handover.md §4: a process compromised in the pod can only run what
# is compiled into this image, and TestGateBinaryHasNoAdminCommands asserts the
# names are absent.
#
# Both base images are pinned by index digest, not just by tag, so a rebuild of
# a moved tag cannot change what this service runs. The digest is the
# multi-platform index; the build platform picks its own manifest from it, and
# every manifest under that index is the same tag. To update deliberately:
#
#   docker manifest inspect golang:1.26.5-bookworm | jq -r .mediaType
#   docker manifest inspect gcr.io/distroless/static-debian12:nonroot
#   # read the index digest:
#   docker pull -q gcr.io/distroless/static-debian12:nonroot
#   docker inspect --format '{{index .RepoDigests 0}}' gcr.io/distroless/static-debian12:nonroot
#
# Recorded on this install:
#   golang:1.26.5-bookworm                        @sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd
#   distroless/static-debian12:nonroot            @sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
#
# The digest form is tag-and-digest, so the file still says which tag these are
# and an operator can compare before updating.
FROM golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/authz-gate ./cmd/authz-gate

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/authz-gate /authz
# Nonroot by uid and group, not by name: a digest-pinned image keeps its
# /etc/passwd, but the numeric form is what the pod spec also asserts, and the
# two should say the same thing.
USER 65532:65532
ENTRYPOINT ["/authz"]
CMD ["serve"]
