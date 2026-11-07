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

local Role = require("src/rbac/Role")
local Log = require("src/util/Log")

local DefaultRoleManager = {
    maxHierarchyLevel = 0
}

--[[
     * In order to use a specific role name matching function, set explicitly the role manager on
     * the Enforcer and rebuild role links (you can optimize by using minimal enforcer constructor).
     *
     * <pre>
     * final Enforcer e = new Enforcer("model.conf");
     * e.setAdapter(new FileAdapter("policies.csv"));
     * e.setRoleManager(new DefaultRoleManager(10, BuiltInFunctions::domainMatch));
     * e.loadPolicy();
     * </pre>
     *
     *
     * @param maxHierarchyLevel the maximized allowed RBAC hierarchy level.
     * @param matchingFunc a matcher for supporting pattern in g
     * @param domainMatchingFunc a matcher for supporting domain pattern in g
]]
function DefaultRoleManager:new(maxHierarchyLevel, matchingFunc, domainMatchingFunc)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.logger = Log.getLogger()
    o.allRoles = {}
    o.maxHierarchyLevel = maxHierarchyLevel
    o.matchingFunc = matchingFunc
    o.domainMatchingFunc = domainMatchingFunc
    return o
end

--[[
    * addMatchingFunc adds a Matching Function to the RM
    * if nil is passed in, it removes the function
]]
function DefaultRoleManager:addMatchingFunc(matchingFunc)
    self.matchingFunc = matchingFunc
end

--[[
    * addDomainMatchingFunc adds a Domain Matching Function to the RM
    * if nil is passed in, it removes the function
]]
function DefaultRoleManager:addDomainMatchingFunc(domainMatchingFunc)
    self.domainMatchingFunc = domainMatchingFunc
end

function DefaultRoleManager:hasRole(role)
    
    if not self.matchingFunc and not self.domainMatchingFunc then
        return self.allRoles[role:getKey()]
    end

    for _, r in pairs(self.allRoles) do
        local flag = true
        if self.matchingFunc then
            if not self.matchingFunc(role.name, r.name) then
                flag = false
            end
        else
            if role.name ~= r.name then
                flag = false
            end
        end

        if self.domainMatchingFunc then
            if not self.domainMatchingFunc(role.domain, r.domain) then
                flag = false
            end
        else
            if role.domain ~= r.domain then
                flag = false
            end
        end
        
        if flag then
            return true
        end
    end
end

function DefaultRoleManager:createRole(name, domain)
    local role = Role:new(name, domain)
    local key
    if domain and domain ~= "" then
        key = domain .. "::" .. name
    else
        key = name
    end
    
    if not self.allRoles[key] then
        self.allRoles[key] = role
    end

    return self.allRoles[key]
end

--  * clear clears all stored data and resets the role manager to the initial state.
function DefaultRoleManager:clear()
    self.allRoles = {}
end

--[[
     * addLink adds the inheritance link between role: name1 and role: name2. aka role: name1
     * inherits role: name2. domain is a prefix to the roles.
]]
function DefaultRoleManager:addLink(name1, name2, ...)
    local domain = {...}
    if #domain > 1 then
        error("domain should be only 1 parameter")
    elseif #domain == 1 then
        domain = domain[1]
    else
        domain = ""
    end

    local role1 = self:createRole(name1, domain)
    local role2 = self:createRole(name2, domain)
    role1:addRole(role2)

    if self.matchingFunc then
        for _, role in pairs(self.allRoles) do
            local flag = true
            if self.domainMatchingFunc then
                if not self.domainMatchingFunc(domain, role.domain) then
                    flag = false
                end
            else
                if domain ~= role.domain then
                    flag = false
                end
            end
            
            if flag then
                if self.matchingFunc(role.name, role1.name) and role1.name ~= role.name then
                    self.allRoles[role:getKey()]:addRole(role1)
                end
                if self.matchingFunc(role.name, role2.name) and role2.name ~= role.name then
                    self.allRoles[role2:getKey()]:addRole(role)
                end
                if self.matchingFunc(role1.name, role.name) and role1.name ~= role.name then
                    self.allRoles[role:getKey()]:addRole(role1)
                end
                if self.matchingFunc(role2.name, role.name) and role2.name ~= role.name then
                    self.allRoles[role2:getKey()]:addRole(role)
                end
            end
        end
    end
end

--[[
     * deleteLink deletes the inheritance link between role: name1 and role: name2. aka role: name1
     * does not inherit role: name2 any more. domain is a prefix to the roles.
]]
function DefaultRoleManager:deleteLink(name1, name2, ...)
    local domain = {...}
    if #domain > 1 then
        error("domain should be only 1 parameter")
    elseif #domain == 1 then
        domain = domain[1]
    else
        domain = ""
    end

    local role1, role2 = self:twoRoleDomainWrapper(name1, name2, domain)

    if not (self:hasRole(role1)) or not (self:hasRole(role2)) then
        error("name1 or name2 does not exist")
    end

    role1:deleteRole(role2)
end

-- hasLink determines whether role: name1 inherits role: name2. domain is a prefix to the roles.
function DefaultRoleManager:hasLink(name1, name2, ...)
    local domain = {...}
    if #domain > 1 then
        error("domain should be only 1 parameter")
    elseif #domain == 1 then
        domain = domain[1]
    else
        domain = ""
    end

    local role1, role2 = self:twoRoleDomainWrapper(name1, name2, domain)

    if role1.name == role2.name then
        return true
    end

    if not (self:hasRole(role1)) or not (self:hasRole(role2)) then
        return false
    end

    if not self.matchingFunc and not self.domainMatchingFunc then
        return role1:hasRole(role2, self.maxHierarchyLevel)
    end

    for _, role in pairs(self.allRoles) do
        local flag = true
        if self.domainMatchingFunc then
            if not self.domainMatchingFunc(domain, role.domain) then
                flag = false
            end
        else
            if domain ~= role.domain then
                flag = false
            end
        end

        if flag then
            if self.matchingFunc then
                if self.matchingFunc(role1.name, role.name) and role:hasRole(role2, self.maxHierarchyLevel, self.matchingFunc, self.domainMatchingFunc) then
                    return true
                end
            else
                if role1.name == role.name and role:hasRole(role2, self.maxHierarchyLevel, self.matchingFunc, self.domainMatchingFunc) then
                    return true
                end
            end
        end
    end
    
    return false
end

--  * getRoles gets the roles that a subject inherits. domain is a prefix to the roles.
function DefaultRoleManager:getRoles(name, ...)
    local domain = {...}
    if #domain > 1 then
        error("domain should be only 1 parameter")
    elseif #domain == 1 then
        domain = domain[1]
    else
        domain = ""
    end

    local role = self:roleDomainWrapper(name, domain)

    if not self:hasRole(role) then
        return {}
    end

    local roles = self:createRole(name, domain):getRoles()

    return roles
end

-- getUsers gets the users that inherits a subject.
function DefaultRoleManager:getUsers(name, ...)
    local domain = {...}
    if #domain > 1 then
        error("domain should be only 1 parameter")
    elseif #domain == 1 then
        domain = domain[1]
    else
        domain = ""
    end

    local targetRole = self:roleDomainWrapper(name, domain)

    local names = {}
    for _, role in pairs(self.allRoles) do
        if role:hasDirectRole(targetRole) then
            table.insert(names, role.name)
        end
    end

    return names
end

-- printRoles prints all the roles to log.
function DefaultRoleManager:printRoles()

    self.logger:info("Roles: ")
    for _, role in pairs(self.allRoles) do
        local text = role:toString()
        if text then 
            self.logger:info(text)
        end
    end

end

function DefaultRoleManager:roleDomainWrapper(name, domain)
    if type(domain) ~= "string" then
        if not domain or #domain==0 then
            domain = ""
        elseif #domain == 1 then
            domain = domain[1]
        else
            error("domain should be only 1 parameter")
        end
    end

    local role = Role:new(name, domain)
    if not self:hasRole(role) then
        return role
    end
    return self:createRole(name, domain)
end

function DefaultRoleManager:twoRoleDomainWrapper(name1, name2, domain)
    return self:roleDomainWrapper(name1, domain), self:roleDomainWrapper(name2, domain)
end

return DefaultRoleManager
