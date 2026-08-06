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

local Util = require("src/util/Util")
local Adapter = require("src/persist/Adapter")

--[[
    * FileAdapter is the file adapter for Casbin.
    * It can load policy from file or save policy to file.
]]
local FileAdapter = {
    readOnly = false
}
setmetatable(FileAdapter, Adapter)

--[[
    * FileAdapter:new(filePath) returns a new FileAdapter
    *
    * @param filePath the path of the policy file.
]]
function FileAdapter:new(filePath)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.filePath = filePath
    return o
end

--[[
    * loadPolicy loads all policy rules from the storage.
]]
function FileAdapter:loadPolicy(model)
    local f = assert(io.open(self.filePath,"r"))

    if f then
        for rawLine in f:lines() do
            local line = Util.trim(rawLine)
            Adapter.loadPolicyLine(line, model)
        end
    end

    f:close()
end

--[[
    * savePolicy saves all policy rules to the storage.
]]
function FileAdapter:savePolicy(model, saveToFilePath)
    local filePath = saveToFilePath
    if not filePath then filePath = self.filePath end

    local f = assert(io.open(filePath,"w"))

    if model.model["p"] then
        for ptype, ast in pairs(model.model["p"]) do
            for _, rule in pairs(ast.policy) do
                local str = ptype .. ", " .. Util.arrayToString(rule) .. "\n"
                f:write(str)
            end
        end
    end

    if model.model["g"] then
        for ptype, ast in pairs(model.model["g"]) do
            for _, rule in pairs(ast.policy) do
                local str = ptype .. ", " .. Util.arrayToString(rule) .. "\n"
                f:write(str)
            end
        end
    end

    f:close()
end

--[[
    * addPolicy adds a policy rule to the storage.
]]
function FileAdapter:addPolicy(sec, ptype, rule)
    error("not implemented")
end

--[[
    * addPolicies adds policy rules to the storage.
]]
function FileAdapter:addPolicies(sec, ptype, rules)
	error("not implemented")
end
--[[
    * removePolicy removes a policy rule from the storage.
]]
function FileAdapter:removePolicy(sec, ptype, rule)
    error("not implemented")
end

--[[
    * updatePolicy updates a policy rule from the storage
]]
function FileAdapter:updatePolicy(sec, ptype, oldRule, newRule)
    error("not implemented")
end

--[[
    * removeFilteredPolicy removes policy rules that match the filter from the storage.
]]
function FileAdapter:removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues)
    error("not implemented")
end

function FileAdapter:updateFilteredPolicies(sec, ptype, newRules, fieldIndex, fieldValues)
    error("not implemented")
end

return FileAdapter