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

local FilteredAdapter = require("src.persist.file_adapter.FilteredAdapter")
local Filter = require("src.persist.file_adapter.Filter")
local Enforcer = require("src.main.Enforcer")
local path = os.getenv("PWD") or io.popen("cd"):read()


describe("FilteredAdapter tests", function ()
    it("init FilteredAdapter test", function ()
        local adapter = FilteredAdapter:new(path .. "/examples/rbac_with_domains_policy.csv")
        local e = Enforcer:new(path .. "/examples/rbac_with_domains_model.conf", adapter)
        assert.is.False(e:HasPolicy("admin", "domain1", "data1", "read"))
    end)

    it("load filtered policy test", function ()
        local adapter = FilteredAdapter:new(path .. "/examples/rbac_with_domains_policy.csv")
        local e = Enforcer:new(path .. "/examples/rbac_with_domains_model.conf", path .. "/examples/rbac_with_domains_policy.csv")
        e:setAdapter(adapter)

        assert.is.True(e:HasPolicy("admin", "domain1", "data1", "read"))
        assert.is.True(e:HasPolicy("admin", "domain2", "data2", "read"))

        local filter = {}
        setmetatable(filter, Filter)
        filter.G = {"", "", "domain1"}
        filter.P = {"", "domain1"}

        e:loadFilteredPolicy(filter)

        assert.is.True(e:HasPolicy("admin", "domain1", "data1", "read"))
        assert.is.False(e:HasPolicy("admin", "domain2", "data2", "read"))
    end)

    it("invalid filter test", function ()
        local adapter = FilteredAdapter:new(path .. "/examples/rbac_with_domains_policy.csv")
        local e = Enforcer:new(path .. "/examples/rbac_with_domains_model.conf", path .. "/examples/rbac_with_domains_policy.csv")
        e:setAdapter(adapter)

        local filter = {"", "domain1"}
        assert.has_error(function ()
            e:loadFilteredPolicy(filter)
        end)
    end)

    it("empty filter test", function ()
        local adapter = FilteredAdapter:new(path .. "/examples/rbac_with_domains_policy.csv")
        local e = Enforcer:new(path .. "/examples/rbac_with_domains_model.conf", path .. "/examples/rbac_with_domains_policy.csv")
        e:setAdapter(adapter)

        e:loadFilteredPolicy(nil)

        assert.is.False(e.adapter.isFiltered)
    end)

    it("unsupported filtered policy test", function ()
        local e = Enforcer:new(path .. "/examples/rbac_with_domains_model.conf", path .. "/examples/rbac_with_domains_policy.csv")

        local filter = {}
        setmetatable(filter, Filter)
        filter.G = {"", "", "domain1"}
        filter.P = {"", "domain1"}
        assert.has_error(function ()
            e:loadFilteredPolicy(filter)
        end)
    end)

    it("invalid file path test", function ()
        local adapter = FilteredAdapter:new(path .. "/examples/does_not_exist_policy.csv")
        local e = Enforcer:new(path .. "/examples/rbac_with_domains_model.conf", path .. "/examples/rbac_with_domains_policy.csv")
        e:setAdapter(adapter)

        assert.has_error(function ()
            e:loadFilteredPolicy(nil)
        end)
    end)
end)