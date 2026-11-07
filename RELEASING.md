<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# Releasing Apache Casbin for Lua (incubating)

The tag workflow only prepares unsigned review input as a CI artifact. It has
read-only repository permissions and no LuaRocks credentials. Branch pushes,
RC tags, final tags, manual dispatch and retries do not publish a release.

## Prepare and review a candidate

1. Merge the reviewed release changes. Check the actual commit's CI and the
   version in `.github/luarocks-template.rockspec` (currently `1.47.0-1`). Keep
   the LuaRocks name `casbin` and import `require("casbin")` compatible.
2. From a clean checkout, run
   `bash scripts/prepare-source.sh <full-commit-sha> <new-output-directory>`.
   The script archives the specified commit, uses an incubating filename,
   checks the legal-file copies and writes an LF-terminated SHA-512 file.
   It refuses to overwrite an existing output directory. This step does not
   sign, stage, tag or publish anything.
3. Extract the archive, review LICENSE/NOTICE/DISCLAIMER and all bundled
   material, run Apache RAT and reconcile its actual coverage. Run `luacheck .`
   and `busted tests -o htest` with the supported Lua runtimes and dependencies.
4. To check the installed package, copy the committed rockspec template to
   `casbin-1.47.0-1.rockspec`, run `luarocks lint` and `luarocks make` against the
   extracted source in an isolated tree, then test from outside the checkout.
   Check CachedEnforcer, DatabaseAdapter, every installed module and the legal
   files under the rock's `doc` directory. These local builds are not releases.
5. The release manager reviews the final archive, signs it with an ASF identity
   whose public key is in Casbin KEYS, and stages the immutable archive,
   `.sha512` and `.asc` in the appropriate ASF development distribution path.
   Download them again and verify the signature/checksum and an extracted build.
6. Seek the required public Casbin PPMC endorsement and Incubator PMC approval
   for those exact bytes. Record both vote/result links. A new candidate with
   changed bytes requires new review/votes. A tag or CI success is not approval.

## Publish approved originals

Only after both approvals, and with the release manager's authorization:

1. Promote the voted source archive and its existing signature/checksum unchanged
   to the ASF release distribution at `incubator/casbin/lua/1.47.0/`. Confirm
   the public downloads match the voted hashes. Do not regenerate the archive
   from the final tag. The final tag must point to the voted source commit.
2. Download the approved archive and verify its checksum/signature. Extract the
   rockspec template from it, retaining its ASF source URL and source directory,
   and name it `casbin-1.47.0-1.rockspec`. Before upload, run `luarocks pack` and
   verify that the resulting source rock embeds the exact approved tarball;
   also install it in a clean consumer and review its contents. Check that the
   package/version has not already been published.
3. An authorized LuaRocks administrator uploads that reviewed rockspec with
   `luarocks upload casbin-1.47.0-1.rockspec --skip-pack`. Supply credentials
   through the administrator's normal secure mechanism. Never use `--force`.
   If a retry finds an existing version, compare its source and metadata first;
   do not overwrite it. Registry control and ASF distribution permissions are
   separate prerequisites.
4. If creating a GitHub Release, attach the voted originals, include the
   incubation disclaimer below, and link the official ASF source, KEYS and
   [verification instructions](https://www.apache.org/info/verification.html).
   Do not replace existing assets or move `latest` before approval. Historical
   releases through 1.46.0 predate Apache incubation.
5. Verify the live LuaRocks page, downloaded rock, installed consumer and GitHub
   display. Announce the approved release and record the public archive links.

References: [ASF Release Policy](https://www.apache.org/legal/release-policy.html),
[Incubation Policy](https://incubator.apache.org/policy/incubation.html#releases),
[distribution guidance](https://incubator.apache.org/guides/distribution.html).

Apache Casbin is an effort undergoing incubation at The Apache Software
Foundation (ASF), sponsored by the Apache Incubator. Incubation is required
of all newly accepted projects until a further review indicates that the
infrastructure, communications, and decision making process have stabilized
in a manner consistent with other successful ASF projects. While incubation
status is not necessarily a reflection of the completeness or stability of
the code, it does indicate that the project has yet to be fully endorsed by
the ASF.
