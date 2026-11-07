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

local Adapter = require("src/persist/Adapter")

-- BatchAdapter is an interface for Casbin adapters with add/remove multiple policies functions.
local BatchAdapter = {}
setmetatable(BatchAdapter, Adapter)

function BatchAdapter:new()
    local o = {}
    setmetatable(o, BatchAdapter)
    self.__index = self
    return o
end

function BatchAdapter:addPolicies(sec, ptype, rules)
    
end

function BatchAdapter:removePolicies(sec, ptype, rules)
    
end

return BatchAdapter