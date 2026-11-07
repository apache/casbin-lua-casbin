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

-- RoleManager provides interface to define the operations for managing roles.
local RoleManager = {}

--[[
     * Clear clears all stored data and resets the role manager to the initial state.
]]
function RoleManager:clear()

end

--[[
     * addLink adds the inheritance link between two roles. role: name1 and role: name2. domain is a
     * prefix to the roles.
     *
     * @param name1 the first role (or user).
     * @param name2 the second role.
     * @param domain the domain the roles belong to.
]]
function RoleManager:addLink(name1, name2, domain)

end

--[[
     * deleteLink deletes the inheritance link between two roles. role: name1 and role: name2.
     * domain is a prefix to the roles.
     *
     * @param name1 the first role (or user).
     * @param name2 the second role.
     * @param domain the domain the roles belong to.
]]
function RoleManager:deleteLink(name1, name2, domain)

end

--[[
     * hasLink determines whether a link exists between two roles. role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     *
     * @param name1 the first role (or a user).
     * @param name2 the second role.
     * @param domain the domain the roles belong to.
     * @return whether name1 inherits name2 (name1 has role name2).
]]
function RoleManager:hasLink(name1, name2, domain)

end

--[[
     * getRoles gets the roles that a user inherits. domain is a prefix to the roles.
     *
     * @param name the user (or a role).
     * @param domain the domain the roles belong to.
     * @return the roles.
]]
function RoleManager:getRoles(name, domain)

end

--[[
     * getUsers gets the users that inherits a role.
     * 
     * @param name the role.
     * @param domain is a prefix to the users (can be used for other purposes).
     * @return the users.
]]
function RoleManager:getUsers(name, domain)

end

--[[
     * printRoles prints all the roles to log.
]]
function RoleManager:printRoles()

end

return RoleManager