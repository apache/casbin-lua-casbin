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

--Adapter is the interface for Casbin adapters.
local Util = require("src.util.Util")
local Adapter = {}
Adapter.__index = Adapter

function Adapter.loadPolicyLine(line, model)
    -- Loads a text line as a policy rule to model.

    if line == "" then
        return
    end

    if line:sub(1, 1) == "#" then
        return
    end

    local tokens = Util.splitEnhanced(line, ',', true)
    local key = tokens[1]
    local sec = key:sub(1, 1)

    if model.model[sec] == nil then
        return
    end
    if model.model[sec][key] == nil then
        return
    end

    model.model[sec][key].policy = model.model[sec][key].policy or {}
    local rules = {}
    for i = 2, #tokens do
        table.insert(rules, tokens[i])
    end
    table.insert(model.model[sec][key].policy, rules)
    model.model[sec][key].policyMap[table.concat(rules, ",")] = #model.model[sec][key].policy
end

--[[
        * loadPolicy loads all policy rules from the storage.
        *
        * An adapter reports a failure either by raising an error with error()
        * or by returning false plus an error message. Casbin turns the latter
        * into an error() as well, so callers can always catch storage failures
        * with pcall() instead of silently getting an empty policy.
        *
        * @param model the model.
]]
function Adapter:loadPolicy(model)

end

--[[
     * savePolicy saves all policy rules to the storage.
     *
     * @param model the model.
]]
function Adapter:savePolicy(model)

end

--[[
     * addPolicy adds a policy rule to the storage.
     * This is part of the Auto-Save feature.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule the rule, like (sub, obj, act).
]]
function Adapter:addPolicy(sec, ptype, rule)

end

--[[
     * removePolicy removes a policy rule from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule the rule, like (sub, obj, act).
]]
function Adapter:removePolicy(sec, ptype, rule)

end

--[[
     * removeFilteredPolicy removes policy rules that match the filter from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
]]
function Adapter:removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues)

end

return Adapter
