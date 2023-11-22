#!/usr/bin/env bats
bats_load_library bats-support
bats_load_library bats-assert
bats_load_library bats-file

@test "tunnel repo with securityCheck secret only" {
  # tunnel repo --format json --output repo.test --scanners=secret https://github.com/khulnasoft-lab/demo-tunnel/
  run ./entrypoint.sh '-b json' '-h repo.test' '-s secret' '-a repo' '-j https://github.com/khulnasoft-lab/demo-tunnel/'
  run diff repo.test ./test/data/repo.test
  echo "$output"
  assert_files_equal repo.test ./test/data/repo.test
}

@test "tunnel image" {
  # tunnel image --severity CRITICAL --output image.test knqyf263/vuln-image:1.2.3
  run ./entrypoint.sh '-a image' '-i knqyf263/vuln-image:1.2.3' '-h image.test' '-g CRITICAL'
  run diff image.test ./test/data/image.test
  echo "$output"
  assert_files_equal image.test ./test/data/image.test
}

@test "tunnel config sarif report" {
  # tunnel config --format sarif --output  config-sarif.test .
  run ./entrypoint.sh '-a config' '-b sarif' '-h config-sarif.test' '-j .'
  run diff config-sarif.test ./test/data/config-sarif.test
  echo "$output"
  assert_files_equal config-sarif.test ./test/data/config-sarif.test
}

@test "tunnel config" {
  # tunnel config --format json --output config.test .
  run ./entrypoint.sh '-a config' '-b json' '-j .' '-h config.test'
  run diff config.test ./test/data/config.test
  echo "$output"
  assert_files_equal config.test ./test/data/config.test
}

@test "tunnel rootfs" {
  # tunnel rootfs --output rootfs.test .
  run ./entrypoint.sh '-a rootfs' '-j .' '-h rootfs.test'
  run diff rootfs.test ./test/data/rootfs.test
  echo "$output"
  assert_files_equal rootfs.test ./test/data/rootfs.test
}

@test "tunnel fs" {
  # tunnel fs --output fs.test .
  run ./entrypoint.sh '-a fs' '-j .' '-h fs.test'
  run diff fs.test ./test/data/fs.test
  echo "$output"
  assert_files_equal fs.test ./test/data/fs.test
}

@test "tunnel fs with securityChecks option" {
  # tunnel fs --format json --scanners=vuln,config --output fs-scheck.test .
  run ./entrypoint.sh '-a fs' '-b json' '-j .' '-s vuln,config,secret' '-h fs-scheck.test'
  run diff fs-scheck.test ./test/data/fs-scheck.test
  echo "$output"
  assert_files_equal fs-scheck.test ./test/data/fs-scheck.test
}


@test "tunnel image with tunnelIgnores option" {
  # cat ./test/data/.tunnelignore1 ./test/data/.tunnelignore2 > ./tunnelignores ; tunnel image --severity CRITICAL  --output image-tunnelignores.test --ignorefile ./tunnelignores knqyf263/vuln-image:1.2.3
  run ./entrypoint.sh '-a image' '-i knqyf263/vuln-image:1.2.3' '-h image-tunnelignores.test' '-g CRITICAL' '-t ./test/data/.tunnelignore1,./test/data/.tunnelignore2'
  run diff image-tunnelignores.test ./test/data/image-tunnelignores.test
  echo "$output"
  assert_files_equal image-tunnelignores.test ./test/data/image-tunnelignores.test
}

@test "tunnel image with sbom output" {
  # tunnel image --format  github knqyf263/vuln-image:1.2.3
  run ./entrypoint.sh  "-a image" "-b github" "-i knqyf263/vuln-image:1.2.3"
  assert_output --partial '"package_url": "pkg:apk/ca-certificates@20171114-r0",' # TODO: Output contains time, need to mock
}

@test "tunnel image with tunnel.yaml config" {
  # tunnel --config=./test/data/tunnel.yaml image alpine:3.10
  run ./entrypoint.sh "-v ./test/data/tunnel.yaml" "-a image" "-i alpine:3.10"
  run diff yamlconfig.test ./test/data/yamlconfig.test
  echo "$output"
  assert_files_equal yamlconfig.test ./test/data/yamlconfig.test
}
