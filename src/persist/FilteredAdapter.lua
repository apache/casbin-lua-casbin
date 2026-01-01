--Copyright 2021 The casbin Authors. All Rights Reserved.
--
--Licensed under the Apache License, Version 2.0 (the "License");
--you may not use this file except in compliance with the License.
--You may obtain a copy of the License at
--
--    http://www.apache.org/licenses/LICENSE-2.0
--
--Unless required by applicable law or agreed to in writing, software
--distributed under the License is distributed on an "AS IS" BASIS,
--WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--See the License for the specific language governing permissions and
--limitations under the License.

local Adapter = require("src/persist/Adapter")

--[[
    * FilteredAdapter is the interface for Casbin adapters supporting filtered policies.
]]
local FilteredAdapter = {}
setmetatable(FilteredAdapter, Adapter)

--[[
    * loadFilteredPolicy loads only policy rules that match the filter.
    * @param model the model.
    * @param filter the filter used to specify which type of policy should be loaded.
    * @raises error if the policy cannot be loaded (e.g., database connection failure).
    *         Implementations MUST raise an error using error() on failure so that
    *         callers can catch it with pcall().
]]
function FilteredAdapter:loadFilteredPolicy(model, filter)
    
end

--[[
    * IsFiltered returns true if the loaded policy has been filtered.
    * @return true if have any filter roles.
]]
function FilteredAdapter:isFiltered()
    
end

return FilteredAdapter