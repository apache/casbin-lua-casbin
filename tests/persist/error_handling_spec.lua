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

local Enforcer = require("src.main.Enforcer")
local Adapter = require("src.persist.Adapter")
local path = os.getenv("PWD") or io.popen("cd"):read()

describe("Error handling tests", function ()
    it("should catch errors from adapter during enforcer initialization", function ()
        -- Create a failing adapter that throws an error during loadPolicy
        local FailingAdapter = {}
        setmetatable(FailingAdapter, Adapter)
        FailingAdapter.__index = FailingAdapter

        function FailingAdapter:new()
            local o = {}
            setmetatable(o, self)
            self.__index = self
            return o
        end

        function FailingAdapter:loadPolicy(model)
            error("Database connection failed: authentication failed")
        end

        local model = path .. "/examples/rbac_model.conf"
        local a = FailingAdapter:new()

        -- Test that the error can be caught with pcall and has the expected message
        local ok, err = pcall(function()
            local e = Enforcer:new(model, a)
        end)

        assert.is.False(ok)
        assert.is.truthy(string.find(err, "Database connection failed"))
        
        -- Also verify using assert.has_error pattern
        assert.has_error(function()
            local a2 = FailingAdapter:new()
            local e2 = Enforcer:new(model, a2)
        end, "Database connection failed")
    end)

    it("should catch errors from adapter during explicit loadPolicy call", function ()
        -- Create an adapter that succeeds initially but fails on explicit loadPolicy
        local DelayedFailingAdapter = {}
        setmetatable(DelayedFailingAdapter, Adapter)
        DelayedFailingAdapter.__index = DelayedFailingAdapter

        function DelayedFailingAdapter:new()
            local o = {}
            setmetatable(o, self)
            self.__index = self
            -- Set isFiltered = true to prevent automatic loadPolicy during Enforcer initialization.
            -- This allows us to test explicit loadPolicy() calls separately.
            o.isFiltered = true
            return o
        end

        function DelayedFailingAdapter:loadPolicy(model)
            error("Database connection failed: wrong password")
        end

        local model = path .. "/examples/rbac_model.conf"
        local a = DelayedFailingAdapter:new()

        -- Create enforcer (won't load policy due to isFiltered=true)
        local e = Enforcer:new(model, a)

        -- Test that calling loadPolicy explicitly raises an error that can be caught
        local ok, err = pcall(function()
            e:loadPolicy()
        end)

        assert.is.False(ok)
        assert.is.truthy(string.find(err, "Database connection failed"))
        
        -- Also verify using assert.has_error pattern
        assert.has_error(function()
            e:loadPolicy()
        end, "wrong password")
    end)

    it("should catch errors from adapter during loadFilteredPolicy call", function ()
        -- Create an adapter that fails during loadFilteredPolicy
        local FilteredFailingAdapter = {}
        setmetatable(FilteredFailingAdapter, Adapter)
        FilteredFailingAdapter.__index = FilteredFailingAdapter

        function FilteredFailingAdapter:new()
            local o = {}
            setmetatable(o, self)
            self.__index = self
            -- Set isFiltered = true to prevent automatic loadPolicy during Enforcer initialization.
            -- This allows us to test loadFilteredPolicy() calls independently.
            o.isFiltered = true
            return o
        end

        function FilteredFailingAdapter:loadFilteredPolicy(model, filter)
            error("Database query failed: connection timeout")
        end

        local model = path .. "/examples/rbac_model.conf"
        local a = FilteredFailingAdapter:new()
        local e = Enforcer:new(model, a)

        -- Test that error from loadFilteredPolicy can be caught
        local ok, err = pcall(function()
            e:loadFilteredPolicy({})
        end)

        assert.is.False(ok)
        assert.is.truthy(string.find(err, "Database query failed"))
        
        -- Also verify using assert.has_error pattern
        assert.has_error(function()
            e:loadFilteredPolicy({})
        end, "connection timeout")
    end)
end)
