#!/usr/bin/env bash
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

set -euo pipefail
if [ "$#" -ne 2 ]; then
  echo "Usage: bash scripts/prepare-source.sh <commit> <new-output-directory>" >&2
  exit 2
fi
commit=$(git rev-parse --verify --end-of-options "${1}^{commit}")
output=$2
version=$(git show "${commit}:.github/luarocks-template.rockspec" |
  sed -n 's/^version = "\([0-9][0-9.]*\)-1"$/\1/p')
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Expected a committed major.minor.patch LuaRocks version" >&2
  exit 1
fi
name="apache-casbin-lua-${version}-incubating-src"
mkdir "$output" # Deliberately fail on an existing destination, including retries.
git archive --format=tar.gz --prefix="$name/" -o "$output/$name.tar.gz" "$commit"
for file in LICENSE NOTICE DISCLAIMER; do
  tar -xOf "$output/$name.tar.gz" "$name/$file" > "$output/$file.check"
  test -s "$output/$file.check"
  tar -xOf "$output/$name.tar.gz" "$name/doc/$file" | cmp - "$output/$file.check"
  rm "$output/$file.check"
done
(cd "$output" && sha512sum "$name.tar.gz" > "$name.tar.gz.sha512")
printf 'Source commit: %s\nUnsigned review input: %s\n' "$commit" "$output/$name.tar.gz"
