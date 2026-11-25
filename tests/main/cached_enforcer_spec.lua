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

        -- Changing the policy drops the cached decisions, so the decision
        -- for ("alice", "data1", "read") is evaluated again and is false now.
        e:RemovePolicy("alice", "data1", "read")

        assert.is.False(e:enforce("alice", "data1", "read"))
        assert.is.False(e:enforce("alice", "data1", "write"))
        assert.is.False(e:enforce("alice", "data2", "read"))
        assert.is.False(e:enforce("alice", "data2", "write"))

        -- Invalidating the cache by hand still works.
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

    it("Test Cache is invalidated on policy and role changes", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = CachedEnforcer:new(model, policy)
        e:enableAutoSave(false)

        assert.is.True(e:enforce("alice", "data2", "read"))
        e:DeleteRoleForUser("alice", "data2_admin")
        assert.is.False(e:enforce("alice", "data2", "read"))

        e:AddRoleForUser("alice", "data2_admin")
        assert.is.True(e:enforce("alice", "data2", "read"))
        e:UpdatePolicy({"data2_admin", "data2", "read"}, {"data2_admin", "data3", "read"})
        assert.is.False(e:enforce("alice", "data2", "read"))

        assert.is.False(e:enforce("bob", "data1", "read"))
        e:AddPolicy("bob", "data1", "read")
        assert.is.True(e:enforce("bob", "data1", "read"))
        e:clearPolicy()
        assert.is.False(e:enforce("bob", "data1", "read"))

        e:loadPolicy()
        assert.is.True(e:enforce("alice", "data2", "read"))
    end)

    it("Test Cache is not written with a decision made before a policy change", function ()
        local model  = path .. "/examples/basic_model.conf"
        local policy  = path .. "/examples/basic_policy.csv"

        local e = CachedEnforcer:new(model, policy)
        e:enableAutoSave(false)

        local version = e:getPolicyVersion()
        e:RemovePolicy("alice", "data1", "read")
        e:syncCacheVersion(e:getPolicyVersion())
        e:setCachedResult("stale", true, version)
        local _, ok = e:getCachedResult("stale")
        assert.is.False(ok)
    end)

    it("Test Cache keys do not collide", function ()
        local model  = path .. "/examples/basic_model.conf"
        local policy  = path .. "/examples/basic_policy.csv"

        local e = CachedEnforcer:new(model, policy)
        e:enableAutoSave(false)
        e:AddPolicy("alice$$data", "x", "read")

        assert.is.True(e:enforce("alice$$data", "x", "read"))
        assert.is.False(e:enforce("alice", "data$$x", "read"))
    end)
end)
