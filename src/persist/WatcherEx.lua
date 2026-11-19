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

local Watcher = require("src.persist.Watcher")

local WatcherEx = {}
setmetatable(WatcherEx, Watcher)
WatcherEx.__index = WatcherEx

-- updateForAddPolicy calls the update callback of other instances to synchronize their policy.
-- It is called after Enforcer:AddPolicy()
function WatcherEx:updateForAddPolicy(sec, ptype, rule)
    
end

-- updateForRemovePolicy calls the update callback of other instances to synchronize their policy.
-- It is called after Enforcer:RemovePolicy()
function WatcherEx:updateForRemovePolicy(sec, ptype, rule)
    
end

-- updateForRemoveFilteredPolicy calls the update callback of other instances to synchronize their policy.
-- It is called after Enforcer:RemoveFilteredNamedGroupingPolicy()
function WatcherEx:updateForRemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues)
    
end

-- updateForSavePolicy calls the update callback of other instances to synchronize their policy.
-- It is called after Enforcer:savePolicy()
function WatcherEx:updateForSavePolicy(model)
    
end

-- updateForAddPolicies calls the update callback of other instances to synchronize their policy.
-- it is called after Enforcer.AddPolicies()
function WatcherEx:updateForAddPolicies(sec, ptype, rules)

end

-- updateForRemovePolicies calls the update callback of other instances to synchronize their policy.
-- It is called after Enforcer.RemovePolicies()
function WatcherEx:updateForRemovePolicies(sec, ptype, rules)

end

return WatcherEx