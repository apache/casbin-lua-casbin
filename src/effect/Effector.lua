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

local Effect = require("src/effect/Effect")

--[[
    * Effector is the interface for Casbin effectors.
]]
local Effector = {}
Effector.__index = Effector
Effector.Effect = {}
setmetatable(Effector.Effect, Effect)
--[[
    * mergeEffects merges all matching results collected by the enforcer into a single decision.
    *
    * @param expr the expression of [policy_effect].
    * @param effects the effects of all matched rules.
    * @param results the matcher results of all matched rules.
    * @return the final effect.
]]

function Effector:mergeEffects(expr, effects, results)
    
end

return Effector