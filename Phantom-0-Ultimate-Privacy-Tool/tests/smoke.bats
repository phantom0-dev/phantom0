#!/usr/bin/env bats

@test "phantomctl loads" {
  run bash -lc './phantomctl version'
  [ "$status" -eq 0 ]
}
