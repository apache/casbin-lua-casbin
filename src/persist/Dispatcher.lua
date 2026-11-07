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

-- Dispatcher is the interface for Casbin dispatcher
local Dispatcher = {}
Dispatcher.__index = Dispatcher

-- addPolicies adds policies rule to all instances.
function Dispatcher:addPolicies(sec, ptype, rules)

end

-- removePolicies removes policies rule from all instances.
function Dispatcher:removePolicies(sec, ptype, rules)

end

-- removeFilteredPolicies removes policy rules that match the filter from all instances.
function Dispatcher:removeFilteredPolicies(sec, ptype, fieldIndex, ...)

end

-- clearPolicy clears all current policy in all instances.
function Dispatcher:clearPolicy()

end

-- updatePolicy updates policy rule from all instances.
function Dispatcher:updatePolicy(sec, ptype, oldRule, newRule)

end

-- UpdatePolicies updates some policy rules from all instance
function Dispatcher:updatePolicies(sec, ptype, oldrules, newRules)

end

-- UpdateFilteredPolicies deletes old rules and adds new rules.
function Dispatcher:updateFilteredPolicies(sec, ptype, oldRules, newRules)

end

return Dispatcher