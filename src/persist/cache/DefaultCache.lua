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
local Cache=require("src/persist/cache/Cache")


local DefaultCache=Cache:new()

function DefaultCache:new()
    local o = {}
    self.__index = self
    setmetatable(o, self)
    o.m={}
    return o
end

function DefaultCache:set(key, value, ...)
    self.m[key] = value
    return nil
end

function DefaultCache:get(key)
    if self.m[key]==nil then
        return nil, false
    else
        return self.m[key], true
    end
end

function DefaultCache:delete(key)
    if self.m[key]==nil then
        return error("there's no such key existing in cache")
    else
        self.m[key]=nil
        return true
    end
end

function DefaultCache:clear()
    self.m = { }
    return true
end

return DefaultCache