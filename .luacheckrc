-- Licensed to the Apache Software Foundation (ASF) under one
-- or more contributor license agreements.  See the NOTICE file
-- distributed with this work for additional information
-- regarding copyright ownership.  The ASF licenses this file
-- to you under the Apache License, Version 2.0 (the
-- "License"); you may not use this file except in compliance
-- with the License.  You may obtain a copy of the License at
--
--   https://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing,
-- software distributed under the License is distributed on an
-- "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
-- KIND, either express or implied.  See the License for the
-- specific language governing permissions and limitations
-- under the License.
codes = true

ignore = {
   "6..",
   "542",
   "212",
   "213",
   "421/ok",
   "421/err",
   "421/errcode",
   "411/ok",
   "411/err",
   "411/errcode",
   "113/unpack",
   "211/require",
   "211/ok",
   "211/err",
   "211/errcode",
   "431/ok",
   "431/err",
   "431/errcode",
   "311/ok",
   "311/err",
   "311/errcode",
   "143/table.unpack",
}

include_files = {
   "src",
   "tests",
}

exclude_files = {
   "tests/config/test.ini",
   "tests/persist/saved_policy.csv",
}

unused_secondaries = false
