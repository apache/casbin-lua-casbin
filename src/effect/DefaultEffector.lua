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

local Effector = require("src/effect/Effector")
--[[
    * DefaultEffector is default effector for Casbin.
]]
local DefaultEffector = {}
setmetatable(DefaultEffector,Effector)
--[[
	* DefaultEffector:new is the constructor for DefaultEffector.
]]
function DefaultEffector:new()
    local o = {}
    setmetatable(o,self)
    self.__index = self
    return o
end
--[[
    * DefaultEffector:mergeEffects merges all matching results collected by the enforcer into a single decision.
]]
function DefaultEffector:mergeEffects(expr, effects)

    local result = false
    local explainIndex = -1

    if expr == "some(where (p_eft == allow))" then
        result = false
        for i, eft in pairs(effects) do
            if eft == self.Effect.ALLOW then
                result = true
                explainIndex = i
                break
            end
        end
    elseif expr == "!some(where (p_eft == deny))" then
        result = true
        for i, eft in pairs(effects) do
            if eft == self.Effect.DENY then
                result = false
                explainIndex = i
                break
            end
        end
    elseif expr == "some(where (p_eft == allow)) && !some(where (p_eft == deny))" then
        result = false
        for i, eft in pairs(effects) do
            if eft == self.Effect.ALLOW then
                result = true
            elseif eft == self.Effect.DENY then
                result = false
                explainIndex = i
                break
            end
        end
    elseif expr == "priority(p_eft) || deny" or expr == "subjectPriority(p_eft) || deny" then
        result = false
        for i, eft in pairs(effects) do
            if eft ~= self.Effect.INDETERMINATE then
                if eft == self.Effect.ALLOW then
                    result = true
                else
                    result = false
                end
                explainIndex = i
                break
            end
        end
    else
        error("unsupported effect")
    end

    return result, explainIndex
end

return DefaultEffector