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

--  * Role represents the data structure for a role in RBAC.
local Role = {}

function Role:new(name, domain)
    local o = {}
    setmetatable(o, self)
    self.__index = self

    o.name = name
    if not domain then
        o.domain = ""
    else
        o.domain = domain
    end
    o.roles = {}

    return o
end

function Role:getKey()
    if self.domain and self.domain ~= "" then
        return self.domain .. "::" .. self.name
    end
    return self.name
end

function Role:addRole(role)
    for _, r in pairs(self.roles) do
        if r.name == role.name and r.domain == role.domain then
            return
        end
    end

    table.insert(self.roles, role)
end

function Role:deleteRole(role)
    for k, r in pairs(self.roles) do
        if r.name == role.name and r.domain == role.domain then
            table.remove(self.roles, k)
        end
    end
end

function Role:hasRole(role, hierarchyLevel, matchingFunc, domainMatchingFunc)
    if self:hasDirectRole(role, matchingFunc, domainMatchingFunc) then
        return true
    end

    if hierarchyLevel <= 0 then
        return false
    end

    for _, r in pairs(self.roles) do
        if r:hasRole(role, hierarchyLevel - 1, matchingFunc, domainMatchingFunc) then
            return true
        end
    end

    return false
end

function Role:hasDirectRole(role, matchingFunc, domainMatchingFunc)

    for _, r in pairs(self.roles) do
        local flag = true
        if matchingFunc then
            if not matchingFunc(role.name, r.name) then
                flag = false
            end
        else
            if role.name ~= r.name then
                flag = false
            end
        end

        if domainMatchingFunc then
            if not domainMatchingFunc(role.domain, r.domain) then
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

    return false
end

function Role:toString()
    local names
    names = self.name .. " < "

    for k, r in pairs(self.roles) do
        if k==1 then 
            names = names .. r.name
        else
            names = names .. ", " .. r.name
        end
    end
    return names
end

function Role:getRoles()
    local names = {}
    for _, r in pairs(self.roles) do
        table.insert(names, r.name)
    end
    return names
end

return Role
