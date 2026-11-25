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

-- DEFAULT_MAX_ENTRIES is the number of decisions a cached enforcer keeps by default.
DefaultCache.DEFAULT_MAX_ENTRIES = 100000

-- new creates a DefaultCache that holds at most maxEntries keys, DEFAULT_MAX_ENTRIES
-- when it is not given. A maxEntries of zero or less means no limit.
function DefaultCache:new(maxEntries)
    local o = {}
    self.__index = self
    setmetatable(o, self)
    o.m={}
    o.size = 0
    o.maxEntries = maxEntries or DefaultCache.DEFAULT_MAX_ENTRIES
    return o
end

-- set puts key and value into the cache. There is no access order to evict by:
-- when the cache is full, adding a new key empties it first.
function DefaultCache:set(key, value, ...)
    if self.m[key] == nil then
        if self.maxEntries > 0 and self.size >= self.maxEntries then
            self:clear()
        end
        self.size = self.size + 1
    end
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
        self.size = self.size - 1
        return true
    end
end

function DefaultCache:clear()
    self.m = { }
    self.size = 0
    return true
end

return DefaultCache