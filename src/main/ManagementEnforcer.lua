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

local InternalEnforcer = require("src.main.InternalEnforcer")
local FunctionMap = require("src.model.FunctionMap")

-- ManagementEnforcer = InternalEnforcer + Management API.
local ManagementEnforcer = {}
setmetatable(ManagementEnforcer, InternalEnforcer)
ManagementEnforcer.__index = ManagementEnforcer

-- GetAllSubjects gets the list of subjects that show up in the current policy.
function ManagementEnforcer:GetAllSubjects()
    return self.model:getValuesForFieldInPolicyAllTypes("p", 1)
end

-- GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
function ManagementEnforcer:GetAllNamedSubjects(ptype)
    return self.model:getValuesForFieldInPolicy("p", ptype, 1)
end

-- GetAllObjects gets the list of objects that show up in the current policy.
function ManagementEnforcer:GetAllObjects()
    return self.model:getValuesForFieldInPolicyAllTypes("p", 2)
end

-- GetAllNamedObjects gets the list of objects that show up in the current named policy.
function ManagementEnforcer:GetAllNamedObjects(ptype)
    return self.model:getValuesForFieldInPolicy("p", ptype, 2)
end

-- GetAllActions gets the list of actions that show up in the current policy.
function ManagementEnforcer:GetAllActions()
    return self.model:getValuesForFieldInPolicyAllTypes("p", 3)
end

-- GetAllNamedActions gets the list of actions that show up in the current named policy.
function ManagementEnforcer:GetAllNamedActions(ptype)
    return self.model:getValuesForFieldInPolicy("p", ptype, 3)
end

-- GetAllRoles gets the list of roles that show up in the current policy.
function ManagementEnforcer:GetAllRoles()
    return self.model:getValuesForFieldInPolicyAllTypes("g", 2)
end

-- GetAllNamedRoles gets the list of roles that show up in the current named policy.
function ManagementEnforcer:GetAllNamedRoles(ptype)
    return self.model:getValuesForFieldInPolicy("g", ptype, 2)
end

-- GetPolicy gets all the authorization rules in the policy.
function ManagementEnforcer:GetPolicy()
    return self:GetNamedPolicy("p")
end

-- GetNamedPolicy gets all the authorization rules in the named policy.
function ManagementEnforcer:GetNamedPolicy(ptype)
    return self.model:getPolicy("p", ptype)
end

-- GetFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
function ManagementEnforcer:GetFilteredPolicy(fieldIndex, ...)
    return self:GetFilteredNamedPolicy("p", fieldIndex, ...)
end

-- GetFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
function ManagementEnforcer:GetFilteredNamedPolicy(ptype, fieldIndex, ...)
    return self.model:getFilteredPolicy("p", ptype, fieldIndex, ...)
end

-- GetGroupingPolicy gets all the role inheritance rules in the policy.
function ManagementEnforcer:GetGroupingPolicy()
    return self:GetNamedGroupingPolicy("g")
end
-- GetNamedGroupingPolicy gets all the role inheritance rules in the policy.
function ManagementEnforcer:GetNamedGroupingPolicy(ptype)
    return self.model:getPolicy("g", ptype)
end

-- GetFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
function ManagementEnforcer:GetFilteredGroupingPolicy(fieldIndex, ...)
    return self:GetFilteredNamedGroupingPolicy("g", fieldIndex, ...)
end
-- GetFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
function ManagementEnforcer:GetFilteredNamedGroupingPolicy(ptype, fieldIndex, ...)
    return self.model:getFilteredPolicy("g", ptype, fieldIndex, ...)
end

-- HasPolicy determines whether an authorization rule exists.
function ManagementEnforcer:HasPolicy(...)
    return self:HasNamedPolicy("p", ...)
end

-- HasNamedPolicy determines whether a named authorization rule exists.
function ManagementEnforcer:HasNamedPolicy(ptype, ...)
    local args = {...}
    if type(args[1]) == "table" then
        return self.model:hasPolicy("p", ptype, args[1])
    end
    return self.model:hasPolicy("p", ptype, args)
end

--[[
    * AddPolicy adds an authorization rule to the current policy.
    * If the rule already exists, the function returns false and the rule will not be added.
    * Otherwise the function returns true by adding the new rule.
]]
function ManagementEnforcer:AddPolicy(...)
    return self:AddNamedPolicy("p", ...)
end

--[[
    * AddNamedPolicy adds an authorization rule to the current named policy.
    * If the rule already exists, the function returns false and the rule will not be added.
    * Otherwise the function returns true by adding the new rule.
]]
function ManagementEnforcer:AddNamedPolicy(ptype, ...)
    local args = {...}
    if type(args[1]) == "table" then
        return self:addPolicy("p", ptype, args[1])
    end
    return self:addPolicy("p", ptype, args)
end

--[[
    * AddPolicies adds authorization rules to the current policy.
    * If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
    * Otherwise the function returns true for the corresponding rule by adding the new rule.
]]
function ManagementEnforcer:AddPolicies(rules)
    return self:AddNamedPolicies("p", rules)
end

--[[
    * AddNamedPolicies adds authorization rules to the current named policy.
    * If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
    * Otherwise the function returns true for the corresponding by adding the new rule.
]]
function ManagementEnforcer:AddNamedPolicies(ptype, rules)
    return self:addPolicies("p", ptype, rules)
end

function ManagementEnforcer:UpdateFilteredPolicies(newPolicies, fieldIndex, fieldValues)
    return self:UpdateFilteredNamedPolicies("p", newPolicies, fieldIndex, fieldValues)
end

function ManagementEnforcer:UpdateFilteredNamedPolicies(ptype, newPolicies, fieldIndex, fieldValues)
    return self:updateFilteredPolicies("p", ptype, newPolicies, fieldIndex, fieldValues)
end

-- RemovePolicy removes an authorization rule from the current policy.
function ManagementEnforcer:RemovePolicy(...)
    return self:RemoveNamedPolicy("p", ...)
end

-- RemoveNamedPolicy removes an authorization rule from the current named policy.
function ManagementEnforcer:RemoveNamedPolicy(ptype, ...)
    local args = {...}
    if type(args[1]) == "table" then
        return self:removePolicy("p", ptype, args[1])
    end
    return self:removePolicy("p", ptype, args)
end

-- RemovePolicies removes authorization rules from the current policy.
function ManagementEnforcer:RemovePolicies(rules)
    return self:RemoveNamedPolicies("p", rules)
end

-- RemoveNamedPolicy removes an authorization rule from the current named policy.
function ManagementEnforcer:RemoveNamedPolicies(ptype, rules)
    return self:removePolicies("p", ptype, rules)
end

-- RemoveFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
function ManagementEnforcer:RemoveFilteredPolicy(fieldIndex, ...)
    return self:RemoveFilteredNamedPolicy("p", fieldIndex, ...)
end

-- RemoveFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
function ManagementEnforcer:RemoveFilteredNamedPolicy(ptype, fieldIndex, ...)
    return self:removeFilteredPolicy("p", ptype, fieldIndex, {...})
end

-- UpdatePolicy updates an authorization rule from the current policy.
function ManagementEnforcer:UpdatePolicy(oldPolicy, newPolicy)
    return self:UpdateNamedPolicy("p", oldPolicy, newPolicy)
end

function ManagementEnforcer:UpdatePolicies(oldPolicies, newPolicies)
    return self:UpdateNamedPolicies("p",  oldPolicies, newPolicies)
end

function ManagementEnforcer:UpdateNamedPolicies(ptype,oldPolicies, newPolicies)
    return self:updatePolicies("p",ptype,oldPolicies, newPolicies)
end

-- UpdateNamedPolicy updates an authorization rule from the current named policy.
function ManagementEnforcer:UpdateNamedPolicy(ptype, oldPolicy, newPolicy)
    return self:updatePolicy("p", ptype, oldPolicy, newPolicy)
end

-- HasGroupingPolicy determines whether a role inheritance rule exists.
function ManagementEnforcer:HasGroupingPolicy(...)
    return self:HasNamedGroupingPolicy("g", ...)
end

-- HasNamedGroupingPolicy determines whether a named role inheritance rule exists.
function ManagementEnforcer:HasNamedGroupingPolicy(ptype, ...)
    local args = {...}
    if type(args[1]) == "table" then
        return self.model:hasPolicy("g", ptype, args[1])
    end
    return self.model:hasPolicy("g", ptype, args)
end

--[[
    * AddGroupingPolicy adds a role inheritance rule to the current policy.
    * If the rule already exists, the function returns false and the rule will not be added.
    * Otherwise the function returns true by adding the new rule.
]]
function ManagementEnforcer:AddGroupingPolicy(...)
    return self:AddNamedGroupingPolicy("g", ...)
end

--[[
    * AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
    * If the rule already exists, the function returns false and the rule will not be added.
    * Otherwise the function returns true by adding the new rule.
]]
function ManagementEnforcer:AddNamedGroupingPolicy(ptype, ...)
    local args = {...}
    if type(args[1]) == "table" then
        return self:addPolicy("g", ptype, args[1])
    end
    return self:addPolicy("g", ptype, args)
end

--[[
    * AddGroupingPolicies adds role inheritance rules to the current policy.
    * If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
    * Otherwise the function returns true for the corresponding policy rule by adding the new rule.
]]
function ManagementEnforcer:AddGroupingPolicies(rules)
    return self:AddNamedGroupingPolicies("g", rules)
end

--[[
    * AddNamedGroupingPolicies adds named role inheritance rules to the current policy.
    * If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
    * Otherwise the function returns true for the corresponding policy rule by adding the new rule.
]]
function ManagementEnforcer:AddNamedGroupingPolicies(ptype, rules)
    return self:addPolicies("g", ptype, rules)
end

-- RemoveGroupingPolicy removes a role inheritance rule from the current policy.
function ManagementEnforcer:RemoveGroupingPolicy(...)
    return self:RemoveNamedGroupingPolicy("g", ...)
end

-- RemoveNamedGroupingPolicy removes a role inheritance rule from the current named policy.
function ManagementEnforcer:RemoveNamedGroupingPolicy(ptype, ...)
    local args = {...}
    if type(args[1]) == "table" then
        return self:removePolicy("g", ptype, args[1])
    end
    return self:removePolicy("g", ptype, args)
end

-- RemoveGroupingPolicies removes role inheritance rules from the current policy.
function ManagementEnforcer:RemoveGroupingPolicies(rules)
    return self:RemoveNamedGroupingPolicies("g", rules)
end

-- RemoveNamedGroupingPolicies removes role inheritance rules from the current named policy.
function ManagementEnforcer:RemoveNamedGroupingPolicies(ptype, rules)
    return self:removePolicies("g", ptype, rules)
end

-- RemoveFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
function ManagementEnforcer:RemoveFilteredGroupingPolicy(fieldIndex, ...)
    return self:RemoveFilteredNamedGroupingPolicy("g", fieldIndex, ...)
end

-- RemoveFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
function ManagementEnforcer:RemoveFilteredNamedGroupingPolicy(ptype, fieldIndex, ...)
    return self:removeFilteredPolicy("g", ptype, fieldIndex, {...})
end

-- UpdateGroupingPolicy updates a role inheritance rule from the current policy.
function ManagementEnforcer:UpdateGroupingPolicy(oldPolicy, newPolicy)
    return self:UpdateNamedGroupingPolicy("g", oldPolicy, newPolicy)
end

-- UpdateNamedGroupingPolicy updates a role inheritance rule from the current named policy.
function ManagementEnforcer:UpdateNamedGroupingPolicy(ptype, oldPolicy, newPolicy)
    return self:updatePolicy("g", ptype, oldPolicy, newPolicy)
end

-- AddFunction adds a customized function to the FunctionMap.
function ManagementEnforcer:AddFunction(name, func)
    FunctionMap:addFunction(name, func)
end

return ManagementEnforcer