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

local Adapter = require("src/persist/Adapter")
local FileAdapter = require("src/persist/file_adapter/FileAdapter")
local Util = require("src/util/Util")
local Filter = require("src/persist/file_adapter/Filter")

--[[
    * FilteredAdapter is the filtered file adapter for Casbin.
    * It can load policy from file or save policy to file and
    * supports loading of filtered policies.
]]
local FilteredAdapter = {
    isFiltered = true
}
setmetatable(FilteredAdapter, Adapter)

function FilteredAdapter:new(filePath)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.filePath = filePath
    o.adapter = FileAdapter:new(filePath)
    o.filter = {}
    o.filter = setmetatable(o.filter, Filter)
    return o
end

--[[
    * loadFilteredPolicy loads only policy rules that match the filter.
    * @param model the model.
    * @param filter the filter used to specify which type of policy should be loaded.
]]
function FilteredAdapter:loadFilteredPolicy(model, filter)
    if self.filePath == "" then
        error("Invalid file path, file path cannot be empty.")
    end

    if filter == nil then
        self.adapter:loadPolicy(model)
        self.isFiltered = false
        return
    end

    if not filter.G or not filter.P then
        error("Invalid filter type.")
    else
        self:loadFilteredPolicyFile(model, filter)
        self.isFiltered = true
    end
end

--[[
    * loadFilteredPolicyFile loads only policy rules that match the filter from file.
]]
function FilteredAdapter:loadFilteredPolicyFile(model, filter)
    local f = assert(io.open(self.filePath,"r"))

    if f then
        for rawLine in f:lines() do
            local line = Util.trim(rawLine)
            if self:filterLine(line, filter) == false then
                Adapter.loadPolicyLine(line, model)
            end
        end
    end

    f:close()
end

--[[
    * Matches the line.
]]
function FilteredAdapter:filterLine(line, filter)
    if filter == nil then
        return false
    end

    local p = Util.split(line, ", ")

    if #p == 0 then
        return true
    end

    local filterSlice = nil
    if Util.trim(p[1]) == "p" then
        filterSlice = filter.P
    elseif Util.trim(p[1]) == "g" then
        filterSlice = filter.G
    end

    if filterSlice == nil then
        filterSlice = {}
    end

    return self:filterWords(p, filterSlice)
end

--[[
    * Matches the words in the specific line.
]]
function FilteredAdapter:filterWords(line, filter)
    if #line < #filter+1 then
        return true
    end

    local skipLine = false
    local i = 1
    for _, v in pairs(filter) do
        i = i + 1
        if #v>0 and Util.trim(v) ~= Util.trim(line[i]) then
            skipLine = true
            break
        end
    end

    return skipLine
end

--[[
    * @return true if have any filter roles.
]]
function FilteredAdapter:isFiltered()
    return self.isFiltered
end

--[[
    * loadPolicy loads all policy rules from the storage.
]]
function FilteredAdapter:loadPolicy(model)
    self.adapter:loadPolicy(model)
    self.isFiltered = false
end

--[[
    * savePolicy saves all policy rules to the storage.
]]
function FilteredAdapter:savePolicy(model)
    self.adapter:savePolicy(model)
end

--[[
    * addPolicy adds a policy rule to the storage.
]]
function FilteredAdapter:addPolicy(sec, ptype, rule)
    self.adapter:addPolicy(sec, ptype, rule)
end

--[[
    * removePolicy removes a policy rule from the storage.
]]
function FilteredAdapter:removePolicy(sec, ptype, rule)
    self.adapter:removePolicy(sec, ptype, rule)
end

--[[
    * removeFilteredPolicy removes policy rules that match the filter from the storage.
]]
function FilteredAdapter:removeFilteredPolicyPolicy(sec, ptype, fieldIndex, fieldValues)
    self.adapter:removeFilteredPolicyPolicy(sec, ptype, fieldIndex, fieldValues)
end

return FilteredAdapter