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

local CachedEnforcer = require("src.main.CachedEnforcer")
local path = os.getenv("PWD") or io.popen("cd"):read()

describe("Cached Enforcer tests", function ()
    it("Test Cache", function ()
        local model  = path .. "/examples/basic_model.conf"
        local policy  = path .. "/examples/basic_policy.csv"

        local e = CachedEnforcer:new(model, policy)
        -- The cache is enabled by default for a new CachedEnforcer.

        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.False(e:enforce("alice", "data1", "write"))
        assert.is.False(e:enforce("alice", "data2", "read"))
        assert.is.False(e:enforce("alice", "data2", "write"))

        -- The cache is enabled, so even if we remove a policy rule, the decision
	    -- for ("alice", "data1", "read") will still be true, as it uses the cached result.
        e:RemovePolicy("alice", "data1", "read")

        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.False(e:enforce("alice", "data1", "write"))
        assert.is.False(e:enforce("alice", "data2", "read"))
        assert.is.False(e:enforce("alice", "data2", "write"))

        -- Now we invalidate the cache, then all first-coming Enforce() has to be evaluated in real-time.
        -- The decision for ("alice", "data1", "read") will be false now.
        e:invalidateCache()

        assert.is.False(e:enforce("alice", "data1", "read"))
        assert.is.False(e:enforce("alice", "data1", "write"))
        assert.is.False(e:enforce("alice", "data2", "read"))
        assert.is.False(e:enforce("alice", "data2", "write"))

        e:AddPolicy("alice", "data1", "read")

        -- Disabling cache skips the cache data and generates result from Enforcer
        e:enableCache(false)

        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.False(e:enforce("alice", "data1", "write"))
        assert.is.False(e:enforce("alice", "data2", "read"))
        assert.is.False(e:enforce("alice", "data2", "write"))
    end)
end)