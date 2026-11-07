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

local Watcher = require("src.persist.Watcher")
local WatcherEx = require("src.persist.WatcherEx")
local WatcherUpdatable = require("src.persist.WatcherUpdatable")

local Enforcer = require("src.main.Enforcer")
local path = os.getenv("PWD") or io.popen("cd"):read()

describe("Watcher test", function ()
    local SampleWatcher = {}
    setmetatable(SampleWatcher, Watcher)

    function SampleWatcher:setUpdateCallback(func)
        return nil
    end

    function SampleWatcher:update()
        return nil
    end

    function SampleWatcher:close()
        return nil
    end

    it("setWatcher test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)
        e:setWatcher(SampleWatcher)
        e:savePolicy()  -- calls Watcher.update()
    end)
end)

describe("WatcherEx test", function ()
    local SampleWatcherEx = {}
    setmetatable(SampleWatcherEx, WatcherEx)

    function SampleWatcherEx:updateForAddPolicy(sec, ptype, rule)
        return nil
    end

    function SampleWatcherEx:updateForRemovePolicy(sec, ptype, rule)
        return nil
    end

    function SampleWatcherEx:updateForRemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues)
        return nil
    end

    function SampleWatcherEx:updateForSavePolicy(model)
        return nil
    end

    it("setWatcherEx test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)
        e:setWatcher(SampleWatcherEx)

        e:savePolicy()                           -- calls WatcherEx:updateForSavePolicy()
        e:AddPolicy("admin", "data1", "read")    -- calls WatcherEx:updateForAddPolicy()
        e:RemovePolicy("admin", "data1", "read") -- calls WatcherEx:updateForRemovePolicy()
        e:RemoveFilteredPolicy(1, "data1")       -- calls WatcherEx:updateForRemoveFilteredPolicy()
        e:AddGroupingPolicy("g:admin", "data1")
        e:RemoveGroupingPolicy("g:admin", "data1")
        e:AddGroupingPolicy("g:admin", "data1")
        e:RemoveFilteredGroupingPolicy(1, "data1")
    end)
end)

describe("WatcherUpdatable test", function ()
    local SampleWatcherUpdatable = {}
    setmetatable(SampleWatcherUpdatable, WatcherUpdatable)

    function SampleWatcherUpdatable:updateForUpdatePolicy(oldRule, newRule)
        return nil
    end

    it("setWatcherUpdatable test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)
        e:setWatcher(SampleWatcherUpdatable)

        e:savePolicy()                                                          -- calls WatcherUpdatable:updateForSavePolicy()
        e:UpdatePolicy({"admin", "data1", "read"}, {"admin", "data2", "read"})  -- calls WatcherUpdatable:UpdateForUpdatePolicy()
    end)
end)