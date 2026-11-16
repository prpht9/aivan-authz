# frozen_string_literal: true

require "digest"
require "json"
require "open3"
require "tmpdir"

# Publishing and deploying the gate.
#
# build.rake ends at an image in the local store. The two steps after that are
# here: a push that proves the registry took the bytes, and a deploy that proves
# the pod is running them. The second half exists because
# doc/pentest-evidence/a.md PA1 found a deployed image seven commits behind the
# tree with nothing in the build noticing.
#
#   rake push           # build the image, push it, and confirm the registry's config digest
#   rake deploy         # push, apply the manifest, roll the Deployment, verify the bytes
#   rake deploy:apply   # manifest only, for a policy change
#   rake deploy:verify  # read-only: is the pod running the image the registry serves, built from HEAD?
#
# AIVAN_NS names the namespace. The default is hermes-agent, the install this
# cluster runs; doc/runbook.md exports the same value. IMAGE comes from
# build.rake and stays overridable there.
module AuthzDeploy
  MANIFEST   = File.expand_path("../deploy/k8s.yaml", __dir__)
  REPO_ROOT  = File.expand_path("..", __dir__)
  DEPLOYMENT = "aivan-authz"
  SELECTOR   = "app=aivan-authz"

  # The house registry serves plain HTTP on :5000. A registry behind TLS needs
  # REGISTRY_SCHEME=https.
  SCHEME = ENV.fetch("REGISTRY_SCHEME", "http")

  # Sent so the registry returns a manifest rather than an index it would have to
  # pick a platform from.
  ACCEPT = %w[
    application/vnd.oci.image.manifest.v1+json
    application/vnd.oci.image.index.v1+json
    application/vnd.docker.distribution.manifest.v2+json
    application/vnd.docker.distribution.manifest.list.v2+json
  ].join(", ")

  module_function

  def namespace
    ENV.fetch("AIVAN_NS", "hermes-agent")
  end

  # DRY_RUN=1 renders and validates the manifest against the API server without
  # changing anything. Only deploy:apply honours it; a rollout cannot be dry-run.
  def dry_run?
    value = ENV["DRY_RUN"].to_s
    !(value.empty? || value == "0")
  end

  # build.rake owns IMAGE and its default. Reading it here keeps the two files
  # loadable in any order and keeps one place to change the tag.
  def image
    IMAGE
  rescue NameError
    ENV.fetch("IMAGE", "docker.home.arpa:5000/aivan-authz:latest")
  end

  # <registry>/<repo>[:tag]. The registry carries a port, so the split is on the
  # first slash and the last colon.
  def image_parts(image = self.image)
    match = %r{\A([^/]+)/(.+?)(?::([^:/]+))?\z}.match(image)
    abort "IMAGE must be <registry>/<repo>[:tag], got #{image.inspect}" unless match
    [match[1], match[2], match[3] || "latest"]
  end

  def registry_manifest(registry, repo, tag)
    url = "#{SCHEME}://#{registry}/v2/#{repo}/manifests/#{tag}"
    body, err, status = Open3.capture3(
      "curl", "-sf", "--max-time", "15", "-H", "Accept: #{ACCEPT}", url
    )
    unless status.success?
      detail = err.strip.empty? ? "" : " (#{err.strip})"
      abort "no manifest for #{repo}:#{tag} at #{url}#{detail}"
    end
    [body, JSON.parse(body)]
  end

  # The registry serves the bytes it stored, so hashing the body reproduces the
  # digest the pod reports in its imageID. This avoids depending on a header the
  # registry is free to format differently.
  def served_digest(registry, repo, tag)
    body, = registry_manifest(registry, repo, tag)
    "sha256:#{Digest::SHA256.hexdigest(body)}"
  end

  def rendered_manifest
    out, err, status = Open3.capture3(
      "envsubst", "${AIVAN_NS}", stdin_data: File.read(MANIFEST)
    )
    abort "envsubst failed on #{MANIFEST}: #{err.strip}" unless status.success?

    # The restriction above leaves the example commands in the header's comments
    # alone. An unsubstituted namespace in an object would be a silent apply into
    # a namespace literally named "${AIVAN_NS}".
    if out.include?("${AIVAN_NS}")
      abort "#{MANIFEST} still contains ${AIVAN_NS} after rendering"
    end
    out
  end

  def kubectl(*args, stdin: nil)
    Open3.capture3("kubectl", *args, stdin_data: stdin.to_s)
  end

  # Secrets the manifest mounts. A missing one is not a failed apply: the
  # Deployment stays pending on the mount and the pod never starts. The purge
  # used to be listed here; it moved to aivan-hud's chart, which mounts
  # aivan-hud-db, so this manifest no longer needs a credential of its own.
  REQUIRED_SECRETS = {
    "aivan-authz-db" => "AIVAN_DB_URL"
  }.freeze

  # A terminating pod is still Running, and during a rollout the old pod's image
  # is the one that would answer this. Only a ready pod is running the rollout's
  # image, so that is the one read.
  def pod_image_id
    out, err, status = kubectl("-n", namespace, "get", "pods", "-l", SELECTOR, "-o", "json")
    abort "kubectl could not list the gate's pods in #{namespace}: #{err.strip}" unless status.success?

    pods = JSON.parse(out)["items"] || []
    ready = pods.reject { |p| p["metadata"]["deletionTimestamp"] }
                .select { |p| p.dig("status", "containerStatuses", 0, "ready") }
    if ready.empty?
      phases = pods.map { |p| p.dig("status", "phase") }.compact
      abort <<~MSG
        no ready pod carries #{SELECTOR} in #{namespace}#{phases.empty? ? '' : " (phase: #{phases.uniq.join(', ')})"}
          status: kubectl -n #{namespace} get pods -l #{SELECTOR}
      MSG
    end

    id = ready.first.dig("status", "containerStatuses", 0, "imageID").to_s
    abort "the ready pod reports no imageID in #{namespace}" if id.empty?
    id
  end

  # Returns [[name, key], ...] for the secrets the manifest needs that are absent
  # or missing their key.
  def missing_secrets
    REQUIRED_SECRETS.filter_map do |name, key|
      out, = kubectl("-n", namespace, "get", "secret", name, "--ignore-not-found", "-o", "json")
      # --ignore-not-found prints nothing for an absent secret.
      data = out.to_s.strip.empty? ? {} : (JSON.parse(out)["data"] || {})
      [name, key] unless data.key?(key)
    end
  end

  # The revision the binary carries, read out of the image itself. The pod's
  # imageID is passed as a name so this reads the bytes that are actually
  # running rather than whatever the local tag happens to point at.
  def image_revision(ref)
    created, err, status = Open3.capture3("docker", "create", ref)
    abort "docker create #{ref} failed: #{err.strip}" unless status.success?
    container = created.strip

    begin
      Dir.mktmpdir("authz-verify") do |dir|
        bin = File.join(dir, "authz")
        _, cp_err, cp_status = Open3.capture3("docker", "cp", "#{container}:/authz", bin)
        abort "could not copy /authz out of #{ref}: #{cp_err.strip}" unless cp_status.success?

        buildinfo, ver_err, ver_status = Open3.capture3("go", "version", "-m", bin)
        abort "go version -m failed on the image's binary: #{ver_err.strip}" unless ver_status.success?

        revision = buildinfo[/vcs\.revision=(\h+)/, 1]
        modified = buildinfo.include?("vcs.modified=true")
        [revision, modified]
      end
    ensure
      Open3.capture3("docker", "rm", "-f", container)
    end
  end

  def head_revision
    out, err, status = Open3.capture3("git", "-C", REPO_ROOT, "rev-parse", "HEAD")
    abort "git rev-parse HEAD failed: #{err.strip}" unless status.success?
    out.strip
  end
end

namespace :build do
  desc "Build the gate's image and push it to the registry, then confirm the digest"
  task push: :image do
    registry, repo, tag = AuthzDeploy.image_parts
    ref = AuthzDeploy.image

    sh "docker", "push", ref

    # A push that printed no error has not been shown to have landed. The
    # registry's manifest names a config digest, and that must be the image that
    # was just built.
    _, doc = AuthzDeploy.registry_manifest(registry, repo, tag)
    if doc["manifests"]
      abort "#{repo}:#{tag} is a multi-platform index; this task builds one platform"
    end

    # podman's .Id is bare hex; the registry names the same config with its
    # algorithm. Comparing the hex is what makes the two say the same thing.
    local_id = `docker image inspect --format '{{.Id}}' #{ref}`.strip
    served   = doc.dig("config", "digest")

    unless served&.delete_prefix("sha256:") == local_id.delete_prefix("sha256:")
      abort <<~MSG
        push did not land: #{repo}:#{tag} names config #{served}, the local image is #{local_id}
      MSG
    end

    puts "pushed #{ref}"
    puts "  manifest #{AuthzDeploy.served_digest(registry, repo, tag)}"
    puts "  config   #{served}"
  end
end

namespace :deploy do
  desc "Render deploy/k8s.yaml for AIVAN_NS and apply it (DRY_RUN=1 validates only)"
  task :apply do
    ns = AuthzDeploy.namespace

    missing = AuthzDeploy.missing_secrets
    unless missing.empty?
      abort <<~MSG
        #{ns} is missing secrets this manifest mounts, so the apply would leave
        the pod pending:
      #{missing.map { |name, key| "  secret/#{name} key #{key}" }.join("\n")}
        deploy/k8s.yaml's header has the kubectl create command.
      MSG
    end

    # -n as well as the rendered manifest: the objects name their namespace when
    # the manifest carries ${AIVAN_NS}, and a manifest without it would
    # otherwise apply into whatever namespace the current context happens to
    # name. Passing both means the two agree or kubectl refuses.
    args = ["kubectl", "-n", ns, "apply", "-f", "-"]
    args += ["--dry-run=server"] if AuthzDeploy.dry_run?

    puts "#{AuthzDeploy.dry_run? ? 'validating' : 'applying'} #{AuthzDeploy::MANIFEST} in #{ns}"
    out, err, status = Open3.capture3(*args, stdin_data: AuthzDeploy.rendered_manifest)
    abort "kubectl apply failed: #{err.strip}" unless status.success?
    puts out
  end

  desc "Restart the gate's Deployment so imagePullPolicy: Always fetches the pushed tag"
  task :rollout do
    ns = AuthzDeploy.namespace
    abort "DRY_RUN=1: a rollout changes the running pod and cannot be dry-run" if AuthzDeploy.dry_run?

    sh "kubectl", "-n", ns, "rollout", "restart", "deployment/#{AuthzDeploy::DEPLOYMENT}"
    # The pod drains for up to 10 s (cmd/authz-gate drainTimeout) and the spec
    # allows 20 s before SIGKILL, so a rollout that hangs past two minutes is a
    # problem worth failing on.
    sh "kubectl", "-n", ns, "rollout", "status",
       "deployment/#{AuthzDeploy::DEPLOYMENT}", "--timeout=120s"
  end

  desc "Read-only: the pod runs the image the registry serves for the tag, built from HEAD"
  task :verify do
    ns = AuthzDeploy.namespace
    registry, repo, tag = AuthzDeploy.image_parts

    available, = AuthzDeploy.kubectl(
      "-n", ns, "get", "deployment", AuthzDeploy::DEPLOYMENT,
      "-o", 'jsonpath={.status.conditions[?(@.type=="Available")].status}'
    )
    abort "deployment/#{AuthzDeploy::DEPLOYMENT} in #{ns} is not Available" unless available.strip == "True"

    served = AuthzDeploy.served_digest(registry, repo, tag)
    live   = AuthzDeploy.pod_image_id

    # The pod reports <name>@<digest>, and that digest is the manifest the
    # registry served. A tag that moved since the pod started shows up here.
    unless live.end_with?(served)
      abort <<~MSG
        the running pod is not what the registry serves for #{repo}:#{tag}
          pod      #{live}
          registry #{served}
        run: rake deploy
      MSG
    end
    puts "pod runs the registry's #{tag} (#{served})"

    revision, modified = AuthzDeploy.image_revision(live)
    if revision.nil?
      abort "the image carries no VCS stamp, so the running binary cannot be joined to a commit"
    end

    head = AuthzDeploy.head_revision
    unless revision == head
      behind = `git -C #{AuthzDeploy::REPO_ROOT} rev-list --count #{revision}..HEAD 2>/dev/null`.strip
      abort <<~MSG
        the running binary is #{revision}, HEAD is #{head}#{behind.empty? ? '' : " (#{behind} commits ahead)"}
        run: rake deploy
      MSG
    end
    puts "running binary is HEAD (#{revision[0, 7]})"

    puts "note: the image carries uncommitted changes (vcs.modified)" if modified
  end
end

desc "Build the gate's image and push it to the registry"
task push: "build:push"

desc "Push, apply the manifest, roll the Deployment, and verify the running bytes"
task :deploy do
  Rake::Task["push"].invoke
  Rake::Task["deploy:apply"].invoke
  if AuthzDeploy.dry_run?
    puts "DRY_RUN=1: stopping after apply; a rollout changes the running pod"
    next
  end
  Rake::Task["deploy:rollout"].invoke
  Rake::Task["deploy:verify"].invoke
end
