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

local FileAdapter = require("src.persist.file_adapter.FileAdapter")
local Model = require("src.model.Model")

local path = os.getenv("PWD") or io.popen("cd"):read()
local basic_path  = path .. "/examples/basic_model.conf"
local basic_policy_path = path .. "/examples/basic_policy.csv"
local rbac_path = path .. "/examples/rbac_model.conf"
local rbac_policy_path = path .. "/examples/rbac_policy.csv"

local save_policy_path = path .. "/tests/persist/saved_policy.csv"

describe("FileAdapter tests", function() 
    
    it("test initialize", function ()
        local f = FileAdapter:new(basic_policy_path)
        assert.are.same(basic_policy_path, f.filePath)
    end)

    it("test loadPolicy: basic_policy", function ()
        local f = FileAdapter:new(basic_policy_path)
        local m = Model:new()
        m:loadModel(basic_path)
        f:loadPolicy(m)

        local rule = {{"alice", "data1", "read"},
                      {"bob", "data2", "write"}}

        assert.is.True(m:hasPolicy("p", "p", rule[1]))
        assert.are.same(rule, m:getPolicy("p","p"))
    end)

    it("test loadPolicy: rbac_policy", function ()
        local f = FileAdapter:new(rbac_policy_path)
        local m = Model:new()
        m:loadModel(rbac_path)
        f:loadPolicy(m)

        local rule = {"alice", "data1", "read"}
        local g_rule = {"alice", "data2_admin"}

        assert.is.True(m:hasPolicy("p", "p", rule))
        assert.is.True(m:hasPolicy("g", "g", g_rule))
    end)

    it("test savePolicy", function ()
        local f = FileAdapter:new(rbac_policy_path)
        local m = Model:new()
        m:loadModel(rbac_path)
        f:loadPolicy(m)
        f:savePolicy(m, save_policy_path)

        local new_file_adapter = FileAdapter:new(save_policy_path)
        local new_model = Model:new()
        new_model:loadModel(rbac_path)
        new_file_adapter:loadPolicy(new_model)

        assert.are.same(new_model:getPolicy("p", "p"),m:getPolicy("p", "p"))
        assert.are.same(new_model:getPolicy("g", "g"),m:getPolicy("g", "g"))
    end)

    it("test not implemented functions", function ()
        local f = FileAdapter:new(basic_policy_path)
        local m = Model:new()
        m:loadModel(basic_path)
        f:loadPolicy(m)

        assert.has_error(function () f:addPolicy() end, "not implemented")
        assert.has_error(function () f:removePolicy() end, "not implemented")
        assert.has_error(function () f:removeFilteredPolicy() end, "not implemented")
    end)
end)
