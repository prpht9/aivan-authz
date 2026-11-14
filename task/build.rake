# frozen_string_literal: true

GO    = ENV.fetch("GO", "go")
GOFMT = ENV.fetch("GOFMT", "gofmt")
IMAGE = ENV.fetch("IMAGE", "docker.home.arpa:5000/aivan-authz:latest")

namespace :build do
  desc "Build both binaries: bin/authz (gate) and bin/authz-admin (operator)"
  task all: %i[gate admin]

  desc "Build the gate, bin/authz"
  task :gate do
    sh GO, "build", "-trimpath", "-o", "bin/authz", "./cmd/authz-gate"
  end

  desc "Build the operator tool, bin/authz-admin"
  task :admin do
    sh GO, "build", "-trimpath", "-o", "bin/authz-admin", "./cmd/authz-admin"
  end

  desc "Build the gate's image (#{IMAGE})"
  task :image do
    sh "docker", "build", "-f", "deploy/Dockerfile", "-t", IMAGE, "."
  end
end

# Only the gate is ever put in an image; the admin binary is an operator tool
# and stays on the workstation (doc/schema-handover.md §4).
desc "Build both binaries (gate and admin) into bin/"
task build: "build:all"

desc "Run the unit tests"
task :test do
  sh GO, "test", "./..."
end

desc "Run the integration tests against a scratch database (needs Postgres)"
task :testdb do
  ENV["AIVAN_TEST_SUPERUSER_URL"] ||= "postgres://postgres@localhost/postgres"
  ENV["AIVAN_TEST_DB_URL"] ||= "postgres://aivan_authz@localhost/aivan_authz_test"
  sh GO, "test", "-tags", "integration", "./..."
end

desc "go vet, then fail if gofmt would rewrite anything"
task :lint do
  sh GO, "vet", "./..."
  unformatted = `#{GOFMT} -l .`.split
  abort "gofmt would rewrite:\n  #{unformatted.join("\n  ")}" unless unformatted.empty?
end
