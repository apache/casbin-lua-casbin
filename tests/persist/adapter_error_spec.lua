--Copyright 2021 The casbin Authors. All Rights Reserved.
--
--Licensed under the Apache License, Version 2.0 (the "License");
--you may not use this file except in compliance with the License.
--You may obtain a copy of the License at
--
--    http://www.apache.org/licenses/LICENSE-2.0
--
--Unless required by applicable law or agreed to in writing, software
--distributed under the License is distributed on an "AS IS" BASIS,
--WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--See the License for the specific language governing permissions and
--limitations under the License.

local Adapter = require("src.persist.Adapter")
local Enforcer = require("src.main.Enforcer")
local FilteredAdapter = require("src.persist.file_adapter.FilteredAdapter")

local path = os.getenv("PWD") or io.popen("cd"):read()
local model_path = path .. "/examples/basic_model.conf"
local policy_path = path .. "/examples/basic_policy.csv"

-- FailingAdapter reports failures the way most database adapters do:
-- by returning false plus an error message instead of raising an error.
local function FailingAdapter(failures)
    local a = {}
    setmetatable(a, Adapter)

    function a:loadPolicy(model)
        if failures.loadPolicy then
            return false, "connection to the database failed"
        end
    end

    function a:savePolicy(model)
        if failures.savePolicy then
            return false, "the database is read only"
        end
    end

    function a:addPolicy(sec, ptype, rule)
        if failures.addPolicy then
            return false, "duplicate key value violates unique constraint"
        end
        return true
    end

    return a
end

describe("adapter error tests", function ()

    it("test loadPolicy error is catchable with pcall", function ()
        local ok, err = pcall(function ()
            Enforcer:new(model_path, FailingAdapter({loadPolicy = true}))
        end)

        assert.is.False(ok)
        assert.is.truthy(string.find(err, "connection to the database failed", 1, true))
    end)

    it("test loadPolicy error of an explicit loadPolicy() call", function ()
        local e = Enforcer:new(model_path, FailingAdapter({}))
        e.adapter = FailingAdapter({loadPolicy = true})

        local ok, err = pcall(function () e:loadPolicy() end)

        assert.is.False(ok)
        assert.is.truthy(string.find(err, "connection to the database failed", 1, true))
    end)

    it("test savePolicy error is catchable with pcall", function ()
        local e = Enforcer:new(model_path, FailingAdapter({savePolicy = true}))

        local ok, err = pcall(function () e:savePolicy() end)

        assert.is.False(ok)
        assert.is.truthy(string.find(err, "the database is read only", 1, true))
    end)

    it("test addPolicy returns the adapter error", function ()
        local e = Enforcer:new(model_path, FailingAdapter({addPolicy = true}))

        local ok, err = e:AddPolicy("alice", "data1", "read")

        assert.is.False(ok)
        assert.is.truthy(string.find(err, "duplicate key value violates unique constraint", 1, true))
        -- the rule must not be added to the model when storage rejected it
        assert.is.False(e:HasPolicy("alice", "data1", "read"))
    end)

    it("test a successful adapter is not reported as an error", function ()
        local e = Enforcer:new(model_path, FailingAdapter({}))

        assert.is.True(e:AddPolicy("alice", "data1", "read"))
        e:savePolicy()
    end)

    -- adapters that return nothing at all (like FileAdapter) keep working
    it("test file adapter still loads", function ()
        local e = Enforcer:new(model_path, policy_path)

        assert.is.True(e:enforce("alice", "data1", "read"))
    end)

    -- FilteredAdapter only delegates, so it must not swallow the wrapped
    -- adapter's failure on its way back to the enforcer.
    it("test filtered adapter propagates the wrapped adapter error", function ()
        local fa = FilteredAdapter:new(policy_path)
        fa.adapter = FailingAdapter({loadPolicy = true, savePolicy = true})

        local ok, err = fa:loadPolicy({})
        assert.is.False(ok)
        assert.are.equals("connection to the database failed", err)

        ok, err = fa:loadFilteredPolicy({}, nil)
        assert.is.False(ok)
        assert.are.equals("connection to the database failed", err)

        ok, err = fa:savePolicy({})
        assert.is.False(ok)
        assert.are.equals("the database is read only", err)
    end)

    it("test filtered adapter reports success of the wrapped adapter", function ()
        local fa = FilteredAdapter:new(policy_path)
        local e = Enforcer:new(model_path, fa)

        e:loadFilteredPolicy(nil)

        assert.is.True(e:enforce("alice", "data1", "read"))
    end)
end)
