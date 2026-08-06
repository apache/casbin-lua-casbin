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

local CoreEnforcer = require("src/main/CoreEnforcer")

--[[
    * tryCall calls fn, usually an adapter operation, and normalizes the way a
    * failure is reported: an adapter may either raise a Lua error or return
    * "false, err", and both must reach the caller instead of being dropped.
    *
    * @param fn the function to call.
    * @return true on success, or false plus the error message on failure.
    *         Operations that the adapter does not implement count as success,
    *         because persistence of them is optional.
]]
local function tryCall(fn)
    local status, ok, err = pcall(fn)

    if status == false then
        local message = tostring(ok)
        if string.sub(message, -15) == "not implemented" then
            -- log, continue
            return true
        end
        return false, message
    end

    if ok == false or (ok == nil and err ~= nil) then
        return false, tostring(err or "unknown error")
    end

    return true
end

-- InternalEnforcer = CoreEnforcer + Internal API.
local InternalEnforcer = {}
setmetatable(InternalEnforcer, CoreEnforcer)
InternalEnforcer.__index = InternalEnforcer

function InternalEnforcer:shouldPersist()
    return self.adapter  and self.autoSave
end

--[[
    * addPolicy adds a rule to the current policy.
]]
function InternalEnforcer:addPolicy(sec, ptype, rule)
    if self.dispatcher~=nil and self.autoNotifyDispatcher then
        self.dispatcher:addPolicies(sec, ptype,{rule})
        return true
    end

    if self.model:hasPolicy(sec, ptype, rule) then
        return false
    end

    if self:shouldPersist() then

        local ok, err = tryCall(function () return self.adapter:addPolicy(sec, ptype, rule) end)
        if not ok then
            return false, err
        end
    end

    self.model:addPolicy(sec, ptype, rule)

    if sec == "g" then
        local rules = {}
        table.insert(rules, rule)
        self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_ADD, ptype, rules)
    end

    if self.watcher and self.autoNotifyWatcher then
        if self.watcher.updateForAddPolicy then
            self.watcher:updateForAddPolicy(sec, ptype, rule)
        else
            self.watcher:update()
        end
    end

    return true
end

--[[
    * addPolicies adds rules to the current policy.
]]
function InternalEnforcer:addPolicies(sec, ptype, rules)
    if self.dispatcher~=nil and self.autoNotifyDispatcher then
        self.dispatcher:addPolicies(sec, ptype,rules)
        return true
    end

    if self.model:hasPolicies(sec, ptype, rules) then
        return false
    end

    if self:shouldPersist() then

        local ok, err = tryCall(function ()
            if self.adapter.addPolicies then
                return self.adapter:addPolicies(sec, ptype, rules)
            end
        end)
        if not ok then
            return false, err
        end
    end

    self.model:addPolicies(sec, ptype, rules)

    if sec == "g" then
        self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_ADD, ptype, rules)
    end

    if self.watcher and self.autoNotifyWatcher then
        if self.watcher.updateForAddPolicies then
            self.watcher:updateForAddPolicies(sec, ptype, rules)
        else
            self.watcher:update()
        end
    end

    return true
end

--[[
    * buildIncrementalRoleLinks provides incremental build the role inheritance relations.
    * @param op Policy operations.
    * @param ptype policy type.
    * @param rules the rules.
]]
function InternalEnforcer:buildIncrementalRoleLinks(op, ptype, rules)
    self.model:buildIncrementalRoleLinks(self.rmMap[ptype], op, "g", ptype, rules)
end

--[[
    * removePolicy removes a rule from the current policy.
]]
function InternalEnforcer:removePolicy(sec, ptype, rule)
    if self.dispatcher~=nil and self.autoNotifyDispatcher then
        self.dispatcher:removePolicies(sec, ptype,{rule})
        return true
    end

    if self:shouldPersist() then

        local ok, err = tryCall(function () return self.adapter:removePolicy(sec, ptype, rule) end)
        if not ok then
            return false, err
        end
    end
    
    local ruleRemoved = self.model:removePolicy(sec, ptype, rule)

    if not ruleRemoved then
        return false
    end

    if sec == "g" then
        local rules = {}
        table.insert(rules, rule)
        self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_REMOVE, ptype, rules)
    end

    if self.watcher and self.autoNotifyWatcher then
        if self.watcher.updateForRemovePolicy then
            self.watcher:updateForRemovePolicy(sec, ptype, rule)
        else
            self.watcher:update()
        end
    end

    return true
end

--[[
    * updatePolicy updates an authorization rule from the current policy.
    * @param sec     the section, "p" or "g".
    * @param ptype   the policy type, "p", "p2", .. or "g", "g2", ..
    * @param oldRule the old rule.
    * @param newRule the new rule.
    * @return succeeds or not.
]]
function InternalEnforcer:updatePolicy(sec, ptype, oldRule, newRule)
    if self.dispatcher~=nil and self.autoNotifyDispatcher then
        self.dispatcher:updatePolicy(sec, ptype,oldRule, newRule)
        return true
    end
    
    if self:shouldPersist() then

        local ok, err = tryCall(function () return self.adapter:updatePolicy(sec, ptype, oldRule, newRule) end)
        if not ok then
            return false, err
        end
    end

    local ruleUpdated = self.model:updatePolicy(sec, ptype, oldRule, newRule)
    
    if not ruleUpdated then
        return false
    end

    if sec == "g" then
        local ok, err = tryCall(function ()
            local oldRules = {}
            table.insert(oldRules, oldRule)
            self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_REMOVE, ptype, oldRules)
        end)
        if not ok then
            return false, err
        end

        ok, err = tryCall(function ()
            local newRules = {}
            table.insert(newRules, newRule)
            self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_ADD, ptype, newRules)
        end)
        if not ok then
            return false, err
        end
    end

    if self.watcher and self.autoNotifyWatcher then
        if self.watcher.updateForUpdatePolicy then
            self.watcher:updateForUpdatePolicy(sec, ptype, oldRule, newRule)
        else
            self.watcher:update()
        end
    end

    return true
end

function InternalEnforcer:updatePolicies(sec, ptype, oldRules, newRules)
    if self.dispatcher~=nil and self.autoNotifyDispatcher then
        self.dispatcher:updatePolicies(sec, ptype,oldRules, newRules)
        return true
    end

    if self:shouldPersist() then

        local ok, err = tryCall(function () return self.adapter:updatePolicies(sec, ptype, oldRules, newRules) end)
        if not ok then
            return false, err
        end
    end

    local ruleUpdated = self.model:updatePolicies(sec, ptype, oldRules, newRules)

    if not ruleUpdated then
        return false
    end

    if sec == "g" then
        local ok, err = tryCall(function ()
            self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_REMOVE, ptype, oldRules)
        end)
        if not ok then
            return false, err
        end

        ok, err = tryCall(function ()
            self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_ADD, ptype, newRules)
        end)
        if not ok then
            return false, err
        end
    end

    if self.watcher and self.autoNotifyWatcher then
        if self.watcher.updateForUpdatePolicies then
            self.watcher:updateForUpdatePolicies(sec, ptype, oldRules, newRules)
        else
            self.watcher:update()
        end
    end

    return true
end

--[[
    * removePolicies removes rules from the current policy.
]]
function InternalEnforcer:removePolicies(sec, ptype, rules)
    if not self.model:hasPolicies(sec, ptype, rules) then
        return false
    end

    if self.dispatcher~=nil and self.autoNotifyDispatcher then
        self.dispatcher:removePolicies(sec, ptype,rules)
        return true
    end

    if self:shouldPersist() then

        local ok, err = tryCall(function ()
            if self.adapter.removePolicies then
                return self.adapter:removePolicies(sec, ptype, rules)
            end
        end)
        if not ok then
            return false, err
        end
    end

    local rulesRemoved = self.model:removePolicies(sec, ptype, rules)

    if not rulesRemoved then
        return false
    end

    if sec == "g" then
        self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_REMOVE, ptype, rules)
    end

    if self.watcher and self.autoNotifyWatcher then
        if self.watcher.updateForRemovePolicies then
            self.watcher:updateForRemovePolicies(sec, ptype, rules)
        else
            self.watcher:update()
        end
    end

    return true
end

--[[
    * removeFilteredPolicy removes rules based on field filters from the current policy.
]]
function InternalEnforcer:removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues)
    if fieldValues == nil or #fieldValues == 0 then
        return false
    end

    if self.dispatcher~=nil and self.autoNotifyDispatcher then
        self.dispatcher:removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues)
        return true
    end

    if self:shouldPersist() then
        
        local ok, err = tryCall(function () return self.adapter:removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues) end)
        if not ok then
            return false, err
        end
    end

    local isRuleRemoved, effects = self.model:removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues)

    if not isRuleRemoved then
        return false
    end

    if sec == "g" then
        self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_REMOVE, ptype, effects)
    end

    if self.watcher and self.autoNotifyWatcher then
        if self.watcher.updateForRemoveFilteredPolicy then
            self.watcher:updateForRemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues)
        else
            self.watcher:update()
        end
    end

    return true
end

function InternalEnforcer:updateFilteredPolicies(sec, ptype, newRules, fieldIndex, fieldValues)
    if fieldValues == nil or #fieldValues == 0 then
        return false
    end

    local oldRules = self.model:getFilteredPolicy(sec, ptype, fieldIndex, fieldValues)
    if self:shouldPersist() then

        local ok, err = tryCall(function () return self.adapter:updateFilteredPolicies(sec, ptype, newRules, fieldIndex, fieldValues) end)
        if not ok then
            return false, err
        end
    end

    if self.dispatcher~=nil and self.autoNotifyDispatcher then
        self.dispatcher:updateFilteredPolicies(sec, ptype, oldRules, newRules)
        return true
    end

    local ruleChanged = self.model:removePolicies(sec, ptype, oldRules)
    self.model:addPolicies(sec, ptype, newRules)
    ruleChanged = ruleChanged and #newRules ~= 0
    if ruleChanged==false then
        return ruleChanged
    end

    if sec == "g" then
        self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_REMOVE, ptype, oldRules)
        self:buildIncrementalRoleLinks(self.model.PolicyOperations.POLICY_ADD, ptype, newRules)
    end

    if self.watcher and self.autoNotifyWatcher then
        if self.watcher.updateForUpdatePolicies then
            self.watcher:updateForUpdatePolicies(oldRules, newRules)
        else
            self.watcher:update()
        end
    end

    return true
end

function InternalEnforcer:getDomainIndex(ptype)
    if not self.model.model["p"] then return end
    if not self.model.model["p"][ptype] then return end

    local p = self.model.model["p"][ptype]
    local pattern = ptype .. "_dom"
    local index = #p.tokens + 1
	for i, token in pairs(p.tokens) do
		if token == pattern then
			index = i
			break
        end
	end
	return index
end

return InternalEnforcer