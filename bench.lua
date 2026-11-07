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
local socket = require("socket")
local Enforcer = require("src.main.Enforcer")
local path = os.getenv("PWD") or io.popen("cd"):read()

local function rawEnforce(sub, obj, act)
    local policy = {{"alice", "data1", "read"}, {"bob", "data2", "write"}}
    for _, rule in pairs(policy) do
        if rule[1] == sub and rule[2] == obj and rule[3] == act then
            return true
        end
    end
    return false
end

local function benchmarkRaw()
    local x = socket.gettime()*1000
    for i = 1, 10000 do
        rawEnforce("alice", "data1", "read")
    end
    x = socket.gettime()*1000 - x
    return x, 10000
end

local function benchmarkBasicModel()
    local e = Enforcer:new(path .. "/examples/basic_model.conf", path .. "/examples/basic_policy.csv")
    e:enableLog(false)
    local x = socket.gettime()*1000
    for i = 1, 10000 do
        _ = e:enforce("alice", "data1", "read")
    end
    x = socket.gettime()*1000 - x
    return x, 10000
end

local function benchmarkRBACModel()
    local e = Enforcer:new(path .. "/examples/rbac_model.conf", path .. "/examples/rbac_policy.csv")
    e:enableLog(false)
    local x = socket.gettime()*1000
    for i = 1, 10000 do
        _ = e:enforce("alice", "data2", "read")
    end
    x = socket.gettime()*1000 - x
    return x, 10000
end

local function benchmarkRBACModelSmall()
    local e = Enforcer:new(path .. "/examples/rbac_model.conf", path .. "/examples/empty_policy.csv")
    e:enableLog(false)

    local pPolicies = {}
    -- 100 roles, 10 resources.
    for i = 1, 100 do
        table.insert(pPolicies, {"group"..tostring(i), "data"..tostring(i%10), "read"})
    end

    e:AddPolicies(pPolicies)

    -- 1000 users.
    local gPolicies = {}
    for i = 1, 1000 do
        table.insert(gPolicies, {"user"..tostring(i), "group"..tostring(i%10)})
    end

    e:AddGroupingPolicies(gPolicies)

    local x = socket.gettime()*1000
    for i = 1, 1000 do
        _ = e:enforce("user501", "data9", "read")
    end
    x = socket.gettime()*1000 - x
    return x, 1000
end

local function benchmarkRBACModelMedium()
    local e = Enforcer:new(path .. "/examples/rbac_model.conf", path .. "/examples/empty_policy.csv")
    e:enableLog(false)

    local pPolicies = {}
    -- 1000 roles, 100 resources.
    for i = 1, 1000 do
        table.insert(pPolicies, {"group"..tostring(i), "data"..tostring(i%100), "read"})
    end

    e:AddPolicies(pPolicies)

    local gPolicies = {}
    -- 10000 users.
    for i = 1, 10000 do
        table.insert(gPolicies, {"user"..tostring(i), "group"..tostring(i%10)})
    end

    e:AddGroupingPolicies(gPolicies)

    local x = socket.gettime()*1000
    for i = 1, 100 do
        _ = e:enforce("user5001", "data99", "read")
    end
    x = socket.gettime()*1000 - x
    return x, 100
end

local function benchmarkRBACModelLarge()
    local e = Enforcer:new(path .. "/examples/rbac_model.conf", path .. "/examples/empty_policy.csv")
    e:enableLog(false)

    local pPolicies = {}
    -- 10000 roles, 1000 resources.
    for i = 1, 10000 do
        table.insert(pPolicies, {"group"..tostring(i), "data"..tostring(i%1000), "read"})
    end

    e:AddPolicies(pPolicies)

    local gPolicies = {}
    -- 100000 users.
    for i = 1, 100000 do
        table.insert(gPolicies, {"user"..tostring(i), "group"..tostring(i%10)})
    end

    e:AddGroupingPolicies(gPolicies)

    local x = socket.gettime()*1000
    for i = 1, 10 do
        _ = e:enforce("user50001", "data999", "read")
    end
    x = socket.gettime()*1000 - x
    return x, 10
end

local function benchmarkRBACModelWithResourceRoles()
    local e = Enforcer:new(path .. "/examples/rbac_with_resource_roles_model.conf", path .. "/examples/rbac_with_resource_roles_policy.csv")
    e:enableLog(false)
    local x = socket.gettime()*1000
    for i = 1, 1000 do
        _ = e:enforce("alice", "data1", "read")
    end
    x = socket.gettime()*1000 - x
    return x, 1000
end

local function benchmarkRBACModelWithDomains()
    local e = Enforcer:new(path .. "/examples/rbac_with_domains_model.conf", path .. "/examples/rbac_with_domains_policy.csv")
    e:enableLog(false)
    local x = socket.gettime()*1000
    for i = 1, 1000 do
        _ = e:enforce("alice", "domain1", "data1", "read")
    end
    x = socket.gettime()*1000 - x
    return x, 1000
end

local function benchmarkABACModel()
    local e = Enforcer:new(path .. "/examples/abac_model.conf", path .. "/examples/empty_policy.csv")
    e:enableLog(false)

    local data1 = {["Name"] = "data1", ["Owner"] = "alice"}

    local x = socket.gettime()*1000
    for i = 1, 1000 do
        _ = e:enforce("alice", data1, "read")
    end
    x = socket.gettime()*1000 - x
    return x, 1000
end

local function benchmarkKeyMatchModel()
    local e = Enforcer:new(path .. "/examples/keymatch_model.conf", path .. "/examples/keymatch_policy.csv")
    e:enableLog(false)
    local x = socket.gettime()*1000
    for i = 1, 1000 do
        _ = e:enforce("alice", "/alice_data/resource1", "GET")
    end
    x = socket.gettime()*1000 - x
    return x, 1000
end

local function benchmarkRBACModelWithDeny()
    local e = Enforcer:new(path .. "/examples/rbac_with_deny_model.conf", path .. "/examples/rbac_with_deny_policy.csv")
    e:enableLog(false)
    local x = socket.gettime()*1000
    for i = 1, 1000 do
        _ = e:enforce("alice", "data1", "read")
    end
    x = socket.gettime()*1000 - x
    return x, 1000
end

local function benchmarkPriorityModel()
    local e = Enforcer:new(path .. "/examples/priority_model.conf", path .. "/examples/priority_policy.csv")
    e:enableLog(false)
    local x = socket.gettime()*1000
    for i = 1, 1000 do
        _ = e:enforce("alice", "data1", "read")
    end
    x = socket.gettime()*1000 - x
    return x, 1000
end

local function runBenchmark()
    local t, o
    local time = {}
    local ops = {}
    local benchName = {}

    t, o = benchmarkRaw()
    table.insert(time, t)
    table.insert(ops, o)
    table.insert(benchName, "Raw")

    t, o = benchmarkBasicModel()
    table.insert(time, t)
    table.insert(ops, o)
    table.insert(benchName, "Basic Model")

    t, o = benchmarkRBACModel()
    table.insert(time, t)
    table.insert(ops, o)
    table.insert(benchName, "RBAC Model")

    t, o = benchmarkRBACModelSmall()
    table.insert(time, t)
    table.insert(ops, o)
    table.insert(benchName, "RBAC Model Small")

    t, o = benchmarkRBACModelMedium()
    table.insert(time, t)
    table.insert(ops, o)
    table.insert(benchName, "RBAC Model Medium")

    t, o = benchmarkRBACModelLarge()
    table.insert(time, t)
    table.insert(ops, o)
    table.insert(benchName, "RBAC Model Large")

    t, o = benchmarkRBACModelWithResourceRoles()
    table.insert(time, t)
    table.insert(ops, o)
    table.insert(benchName, "RBAC Model with Resources")

    t, o = benchmarkRBACModelWithDomains()
    table.insert(time, t)
    table.insert(ops, o)
    table.insert(benchName, "RBAC Model with Domains")

    t, o = benchmarkABACModel()
    table.insert(time, t)
    table.insert(ops, o)
    table.insert(benchName, "ABAC Model")

    t, o = benchmarkKeyMatchModel()
    table.insert(time, t)
    table.insert(ops, o)
    table.insert(benchName, "KeyMatch Model")

    t, o = benchmarkRBACModelWithDeny()
    table.insert(time, t)
    table.insert(ops, o)
    table.insert(benchName, "RBAC Model with Deny")

    t, o = benchmarkPriorityModel()
    table.insert(time, t)
    table.insert(ops, o)
    table.insert(benchName, "Priority Model")

    print("Benchmark:")
    for k, v in pairs(benchName) do
        print(v .. ":", "\tTotal ops = " .. tostring(ops[k]), "\tTime per op = " .. string.format("%.4f ms", time[k]/ops[k]))
    end
end

runBenchmark()