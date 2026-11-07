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

local Enforcer = require("src.main.Enforcer")
local path = os.getenv("PWD") or io.popen("cd"):read()

describe("Internal API tests", function ()
    it("Add Policy test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.False(e:enforce("alice", "data1", "write"))
        e:addPolicy("p", "p", {"alice", "data1", "write"})
        assert.is.True(e:enforce("alice", "data1", "write"))

        assert.is.False(e:enforce("bob", "data2", "read"))
        e:addPolicy("g", "g", {"bob", "data2_admin"})
        assert.is.True(e:enforce("bob", "data2", "read"))
    end)

    it("Remove Policy tests", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.True(e:enforce("alice", "data1", "read"))
        e:removePolicy("p", "p", {"alice", "data1", "read"})
        assert.is.False(e:enforce("alice", "data1", "read"))

        assert.is.True(e:enforce("alice", "data2", "read"))
        assert.is.True(e:enforce("alice", "data2", "write"))
        e:removePolicy("g", "g", {"alice", "data2_admin"})
        assert.is.False(e:enforce("alice", "data2", "read"))
        assert.is.False(e:enforce("alice", "data2", "write"))
    end)

    it("Update Policy tests", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.False(e:enforce("alice", "data1", "write"))
        e:updatePolicy("p", "p", {"alice", "data1", "read"}, {"alice", "data1", "write"})
        assert.is.False(e:enforce("alice", "data1", "read"))
        assert.is.True(e:enforce("alice", "data1", "write"))

        assert.is.True(e:enforce("alice", "data2", "read"))
        assert.is.False(e:enforce("bob", "data2", "read"))
        e:updatePolicy("g", "g", {"alice", "data2_admin"}, {"bob", "data2_admin"})
        assert.is.False(e:enforce("alice", "data2", "read"))
        assert.is.True(e:enforce("bob", "data2", "read"))
    end)

    it("Add/Remove Policies test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)

        local rules = {
            {"cathy", "data1", "read"},
            {"cathy", "data1", "write"}
        }
        assert.is.False(e:enforce("cathy", "data1", "read"))
        assert.is.False(e:enforce("cathy", "data1", "write"))
        e:addPolicies("p", "p", rules)
        assert.is.True(e:enforce("cathy", "data1", "read"))
        assert.is.True(e:enforce("cathy", "data1", "write"))

        e:removePolicies("p", "p", rules)
        assert.is.False(e:enforce("cathy", "data1", "read"))
        assert.is.False(e:enforce("cathy", "data1", "write"))

        rules = {
            {"cathy", "data2_admin"}
        }

        assert.is.False(e:enforce("cathy", "data2", "read"))
        assert.is.False(e:enforce("cathy", "data2", "write"))
        e:addPolicies("g", "g", rules)
        assert.is.True(e:enforce("cathy", "data2", "read"))
        assert.is.True(e:enforce("cathy", "data2", "write"))
    end)

    it("removeFilteredPolicy test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)

        local rules = {
            {"cathy", "data1", "read"},
            {"cathy", "data1", "write"}
        }
        e:addPolicies("p", "p", rules)

        assert.is.True(e:enforce("cathy", "data1", "read"))
        assert.is.True(e:enforce("cathy", "data1", "write"))

        e:removeFilteredPolicy("p", "p", 0, {"cathy"})
        assert.is.False(e:enforce("cathy", "data1", "read"))
        assert.is.False(e:enforce("cathy", "data1", "write"))

        assert.is.True(e:enforce("alice", "data2", "read"))
        assert.is.True(e:enforce("alice", "data2", "write"))

        e:removeFilteredPolicy("g", "g", 0, {"alice"})
        e.model:printPolicy()
        assert.is.False(e:enforce("alice", "data2", "read"))
        assert.is.False(e:enforce("alice", "data2", "write"))
    end)
end)