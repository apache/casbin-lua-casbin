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

local BuiltInFunctions = require("src.util.BuiltInFunctions")

local FunctionMap = {
    ["keyMatch"] = BuiltInFunctions.keyMatchFunc,
    ["keyGet"] = BuiltInFunctions.keyGetFunc,
    ["keyMatch2"] = BuiltInFunctions.keyMatch2Func,
    ["keyGet2"] = BuiltInFunctions.keyGet2Func,
    ["keyMatch3"] = BuiltInFunctions.keyMatch3Func,
    ["keyMatch4"] = BuiltInFunctions.keyMatch4Func,
    ["keyMatch5"] = BuiltInFunctions.keyMatch5Func,
    ["regexMatch"] = BuiltInFunctions.regexMatchFunc,
    ["IPMatch"] = BuiltInFunctions.IPMatchFunc,
    ["globMatch"] = BuiltInFunctions.globMatchFunc,
}

-- FunctionMap provides a set of built in functions
function FunctionMap:new()
    local o = {}
    for k, v in pairs(FunctionMap) do
        o[k] = v
    end
    return o
end

-- Add new built-in function to FunctionMap
function FunctionMap:addFunction(key, func)
    if not self[key] then
        self[key] = func
    end
end

return FunctionMap