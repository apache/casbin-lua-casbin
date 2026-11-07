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

local Util = require("src/util/Util")
local Log = require("src/util/Log")

-- model's struct is map<string, map<string, Assertion>>
local Policy = {}

function Policy:new()
    local o = {}
    o.logger = Log.getLogger()
    setmetatable(o, self)
    self.__index = self
    return o
end

--[[
    * buildRoleLinks initializes the roles in RBAC.
    *
    * @param rm the role manager.
]]
function Policy:buildRoleLinks(rmMap)
    if self.model["g"] then
        for ptype, ast in pairs(self.model["g"]) do
            local rm = rmMap[ptype]
            ast:buildRoleLinks(rm)
        end
    end
end

--[[
    * printPolicy prints the policy to log.
]]
function Policy:printPolicy()
    self.logger:info("Policy: \n")
    if self.model["p"] then
        for k, ast in pairs(self.model["p"]) do
            self.logger:info("%s:   %s:", k, ast.value)
            self.logger:info(ast.policy)
        end
    end

    if self.model["g"] then
        for k, ast in pairs(self.model["g"]) do
            self.logger:info("%s:   %s:", k, ast.value)
            self.logger:info(ast.policy)
        end
    end
end

--[[
    * printPolicyMap prints the policyMap to log.
]]
function Policy:printPolicyMap()
    self.logger:info("policyMap: \n")
    if self.model["p"] then
        for k, ast in pairs(self.model["p"]) do
            self.logger:info("%s:   key,value", k )
            for i,v in pairs(ast.policyMap) do
                self.logger:info("{%s,%s}", i, v)
            end
        end
    end

    if self.model["g"] then
        for k, ast in pairs(self.model["g"]) do
            self.logger:info("%s:   key,value", k )
            for i,v in pairs(ast.policyMap) do
                self.logger:info("{%s,%s}", i, v)
            end
        end
    end
end

--[[
    * savePolicyToText saves the policy to the text.
    *
    * @return the policy text.
]]
function Policy:savePolicyToText()
    local res = ""

    if self.model["p"] then
        for key, ast in pairs(self.model["p"]) do
            for _, rule in pairs(ast.policy) do
                local x = string.format("%s, %s\n", key, table.concat(rule, ", "))
                res = res .. x
            end
        end
    end

    if self.model["g"] then
        for key, ast in pairs(self.model["g"]) do
            for _, rule in pairs(ast.policy) do
                local x = string.format("%s, %s\n", key, table.concat(rule, ", "))
                res = res .. x
            end
        end
    end

    return res
end

--[[
    * clearPolicy clears all current policy.
]]
function Policy:clearPolicy()
    if self.model["p"] then
        for _, v in pairs(self.model["p"]) do
            v.policy = {}
            v.policyMap = {}
        end
    end

    if self.model["g"] then
        for _, v in pairs(self.model["g"]) do
            v.policy = {}
            v.policyMap = {}
        end
    end
end

--[[
    * getPolicy gets all rules in a policy.
    *
    * @param sec the section, "p" or "g".
    * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
    * @return the policy rules of section sec and policy type ptype.
]]
function Policy:getPolicy(sec, ptype)
    local policy = Util.deepCopy(self.model[sec][ptype].policy)
    return policy
end

--[[
    * getFilteredPolicy gets rules based on field filters from a policy.
    *
    * @param sec the section, "p" or "g".
    * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
    * @param fieldIndex the policy rule's start index to be matched.
    * @param ... fieldValues the field values to be matched, value ""
    *                    means not to match this field.
    * @return the filtered policy rules of section sec and policy type ptype.
]]
function Policy:getFilteredPolicy(sec, ptype, fieldIndex, ...)
    local res = {}
    local fieldValues = {...}
    if type(fieldValues[1]) == "table" then
        fieldValues = fieldValues[1]
    end

    if not self.model[sec] then return res end
    if not self.model[sec][ptype] then return res end

    for _, rule in pairs(self.model[sec][ptype].policy) do
        local matched = true
        for i, v in ipairs(fieldValues) do
            if v ~= "" and rule[fieldIndex + i] ~= v then
                matched = false
                break
            end
        end
        if matched then
            table.insert(res, rule)
        end
    end

    return res
end

--[[
    * hasPolicy determines whether a model has the specified policy rule.
    *
    * @param sec the section, "p" or "g".
    * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
    * @param rule the policy rule.
    * @return whether the rule exists.
]]
function Policy:hasPolicy(sec, ptype, rule)
    if self.model[sec][ptype].policyMap[table.concat(rule,",")] == nil then
        return false
    else
        return true
    end
end

--[[
    * hasPolicies determines whether a model has any of the specified policies.
    *
    * @param sec the section, "p" or "g".
    * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
    * @param rules the policies rules.
    * @return whether one is found.
]]
function Policy:hasPolicies(sec, ptype, rules)
    for i = 1, #rules do
        if self:hasPolicy(sec, ptype, rules[i]) then
            return true
        end
    end
    return false
end


--[[
    * addPolicy adds a policy rule to the model.
    *
    * @param sec the section, "p" or "g".
    * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
    * @param rule the policy rule.
    * @return succeeds or not.
]]
function Policy:addPolicy(sec, ptype, rule)
    if not self:hasPolicy(sec, ptype, rule) then
        table.insert(self.model[sec][ptype].policy, rule)
        self.model[sec][ptype].policyMap[table.concat(rule,",")] = #self.model[sec][ptype].policy
        if sec == "p" and self.model[sec][ptype].priorityIndex > 0 then
            local idxInsert=tonumber(rule[self.model[sec][ptype].priorityIndex])
            if rule[self.model[sec][ptype].priorityIndex]~= nil then
                local i = #self.model[sec][ptype].policy-1
                for j = i, 1, -1 do
                    local idx=tonumber(self.model[sec][ptype].policy[i+1][self.model[sec][ptype].priorityIndex])
                    if idx < idxInsert then
                        self.model[sec][ptype].policy[i+1] = self.model[sec][ptype].policy[i]
                        self.model[sec][ptype].policyMap[table.concat(self.model[sec][ptype].policy[i+1], ",")] = i+1
                    else
                        i = j
                        break
                    end
                    i = j
                end
                self.model[sec][ptype].policy[i] = rule
                self.model[sec][ptype].policyMap[table.concat(rule,",")] = i
            end
        end
        return true
    end
    return false
end

--[[
    * addPolicies adds policy rules to the model.
    * @param sec the section, "p" or "g".
    * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
    * @param rules the policy rules.
    * @return succeeds or not.
]]
function Policy:addPolicies(sec, ptype, rules)
    return self:addPoliciesWithAffected(sec, ptype, rules) ~= 0
end

--[[
    * addPoliciesWithAffected adds policy rules to the model.
    * @param sec the section, "p" or "g".
    * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
    * @param rules the policy rules.
    * @return effected.
]]
function Policy:addPoliciesWithAffected(sec, ptype, rules)
    local effected = {}
    for _, rule in pairs(rules) do
        if self:addPolicy(sec, ptype, rule) then
            table.insert(effected, rule)

        end
    end
    return effected
end

--[[
    * UpdatePolicy updates a policy rule from the model.
    *
    * @param sec the section, "p" or "g".
    * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
    * @param oldRule the old rule.
    * @param newRule the new rule.
    * @return succeeds or not.
]]
function Policy:updatePolicy(sec, ptype, oldRule, newRule)
    if not self:hasPolicy(sec, ptype, oldRule) then return false end
    local key = table.concat(oldRule,",")
    local index = self.model[sec][ptype].policyMap[key]
    self.model[sec][ptype].policy[index] = newRule
    self.model[sec][ptype].policyMap[key] = nil
    local tempKey = table.concat(newRule,",")
    self.model[sec][ptype].policyMap[tempKey] = index
    return true
end

-- Updates multiple policy rules from the model.
function Policy:updatePolicies(sec, ptype, oldRules, newRules)
    local rollbackFlag = false
    local modifiedRuleIndex = {}

    local newIndex = 1
    for oldIndex, oldRule in pairs(oldRules) do
        local oldPolicy = table.concat(oldRule, ",")
        if self.model[sec][ptype].policyMap[oldPolicy] == nil then
            rollbackFlag = true
            break
        end
        local index = self.model[sec][ptype].policyMap[oldPolicy]

        self.model[sec][ptype].policy[index] = newRules[newIndex]
        self.model[sec][ptype].policyMap[oldPolicy] = nil
        self.model[sec][ptype].policyMap[table.concat(newRules[newIndex], ",")] = index
        modifiedRuleIndex[index] = {oldIndex, newIndex}
        newIndex = newIndex+1
    end

    if rollbackFlag then
        for index, oldNewIndex in pairs(modifiedRuleIndex)  do
            self.model[sec][ptype].policy[index] = oldRules[oldNewIndex[1]]
            local oldPolicy = table.concat(oldRules[oldNewIndex[1]], ",")
            local newPolicy = table.concat(newRules[oldNewIndex[2]], ",")
            self.model[sec][ptype].policyMap[newPolicy] = nil
            self.model[sec][ptype].policyMap[oldPolicy] = index
        end
        return false
    end
    return true
end

function Policy:updateFilteredPolicies(sec, ptype, fieldIndex, fieldValues,newRules)
    local tmp = {}
    local res = false
    local effects = {}
    local newRulesIndex=1

    if not self.model[sec] then return res end
    if not self.model[sec][ptype] then return res end
    self.model[sec][ptype].policyMap = {}
    for _, rule in pairs(self.model[sec][ptype].policy) do
        local matched = true
        for i, value in pairs(fieldValues) do
            if value ~= "" and rule[fieldIndex+i] ~= value then
                matched = false
                break
            end
        end

        if matched then
            table.insert(effects, rule)
            table.insert(tmp, newRules[newRulesIndex])
            local tempKey1 = table.concat(newRules[newRulesIndex],",")
            self.model[sec][ptype].policyMap[tempKey1] = #tmp
            newRulesIndex = newRulesIndex+1
            res = true
        else
            table.insert(tmp, rule)
            local tempKey = table.concat(rule,",")
            self.model[sec][ptype].policyMap[tempKey] = #tmp
        end
    end

    if res then
        self.model[sec][ptype].policy = tmp
    end
    return res, effects
end

--[[
    * removePolicy removes a policy rule from the model.
    *
    * @param sec the section, "p" or "g".
    * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
    * @param rule the policy rule.
    * @return succeeds or not.
]]
function Policy:removePolicy(sec, ptype, rule)
    if self:hasPolicy(sec,ptype,rule) then
        local key = table.concat(rule,",")
        local index = self.model[sec][ptype].policyMap[key]
        table.remove(self.model[sec][ptype].policy, index)
        self.model[sec][ptype].policyMap[key] = nil
        local length = #self.model[sec][ptype].policy
        for i=index, length, 1 do
            local tempKey = table.concat(self.model[sec][ptype].policy[i],",")
            self.model[sec][ptype].policyMap[tempKey] = i
        end
        return true
    end
    return false
end

--[[
    * removePolicies removes rules from the current policy.
    * @param sec the section, "p" or "g".
    * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
    * @param rules the policy rules.
    * @return succeeds or not.
]]
function Policy:removePolicies(sec, ptype, rules)
    return #self:removePoliciesWithEffected(sec, ptype, rules) ~= 0
end

--[[
    * removePoliciesWithEffected removes policy rules from the model, and returns effected rules.
    *
    * @param sec the section, "p" or "g".
    * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
    * @param rules the policy rules.
    *
    * @return effected.
]]
function Policy:removePoliciesWithEffected(sec, ptype, rules)
    local effected={}
    for _,rule in pairs(rules) do
        if self:removePolicy(sec,ptype,rule) then
            table.insert(effected,rule)
        end
    end
    return effected
end

--[[
    * removeFilteredPolicy removes policy rules based on field filters from the model.
    *
    * @param sec the section, "p" or "g".
    * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
    * @param fieldIndex the policy rule's start index to be matched.
    * @param ... fieldValues the field values to be matched, value ""
    *                    means not to match this field.
    * @return succeeds or not.
]]
function Policy:removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues)
    local tmp = {}
    local res = false
    local effects = {}

    if not self.model[sec] then return res end
    if not self.model[sec][ptype] then return res end
    self.model[sec][ptype].policyMap = {}
    for _, rule in pairs(self.model[sec][ptype].policy) do
        local matched = true
        for i, value in pairs(fieldValues) do
            if value ~= "" and rule[fieldIndex+i] ~= value then
                matched = false
                break
            end
        end

        if matched then
            table.insert(effects, rule)
            res = true
        else
            table.insert(tmp, rule)
            local tempKey = table.concat(rule,",")
            self.model[sec][ptype].policyMap[tempKey] = #tmp
        end
    end
    if #tmp ~= #self.model[sec][ptype].policy then
        self.model[sec][ptype].policy = tmp
    end
    return res, effects
end

--[[
    * getValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
    *
    * @param sec the section, "p" or "g".
    * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
    * @param fieldIndex the policy rule's index.
    * @return the field values specified by fieldIndex.
]]
function Policy:getValuesForFieldInPolicy(sec, ptype, fieldIndex)
    local values = {}

    for _, rule in pairs(self.model[sec][ptype].policy) do
        values[#values + 1] = rule[fieldIndex]
    end

    values = Util.arrayRemoveDuplications(values)
    return values
end

function Policy:getValuesForFieldInPolicyAllTypes(sec, fieldIndex)
    local values = {}

    for ptype, _ in pairs(self.model[sec]) do
        local tvalues = self:getValuesForFieldInPolicy(sec, ptype, fieldIndex)
        for _, v in pairs(tvalues) do
            table.insert(values, v)
        end
    end

    return values
end

function Policy:buildIncrementalRoleLinks(rm, op, sec, ptype, rules)
    if sec == "g" then
        self.model[sec][ptype]:buildIncrementalRoleLinks(rm, op, rules)
    end
end

return Policy
