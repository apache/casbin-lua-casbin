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

local Enforcer = require("src.main.Enforcer")
local DefaultCache=require("src.persist.cache.DefaultCache")

-- CachedEnforcer wraps Enforcer and provides decision cache
local CachedEnforcer = {}
setmetatable(CachedEnforcer, Enforcer)

-- Creates a cached enforcer via file or DB.
function CachedEnforcer:new(model, adapter)
    local e = Enforcer:new(model, adapter)
    self.__index = self
    setmetatable(e, self)
    e.cacheEnabled = true
    e.m = DefaultCache:new()
    e.cacheVersion = e:getPolicyVersion()
    return e
end

-- enableCache determines whether to enable cache on Enforce(). When enableCache is enabled, cached result (true | false) will be returned for previous decisions.
function CachedEnforcer:enableCache(enabled)
    if enabled then
        self.cacheEnabled = true
    else
        self.cacheEnabled = false
    end
end

-- enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
-- if rvals is not string , ingore the cache
function CachedEnforcer:enforce(...)
    if not self.cacheEnabled then
        return Enforcer.enforce(self, ...)
    end

    local key = self:getCacheKey(...)
    if key == nil then
        return Enforcer.enforce(self, ...)
    end

    local version = self:getPolicyVersion()
    self:syncCacheVersion(version)

    local res, ok = self:getCachedResult(key)
    if ok then
        return res
    end

    res = Enforcer.enforce(self, ...)

    self:setCachedResult(key, res, version)
    return res
end

-- syncCacheVersion drops all cached decisions when the policy has changed since they were cached.
function CachedEnforcer:syncCacheVersion(version)
    if self.cacheVersion ~= nil and version <= self.cacheVersion then
        return
    end
    self.m:clear()
    self.cacheVersion = version
end

-- getCacheKey returns the cache key of a request, or nil when the request
-- cannot be cached. Each value is length-prefixed so that different requests
-- never share a key.
function CachedEnforcer:getCacheKey(...)
    local parts = {}
    for i = 1, select("#", ...) do
        local rval = select(i, ...)
        if type(rval) ~= "string" then
            return nil
        end
        table.insert(parts, #rval .. ":" .. rval)
    end
    return table.concat(parts)
end

function CachedEnforcer:getCachedResult(key)
    return self.m:get(key)
end

-- setCachedResult caches a decision, unless the policy has changed since the
-- decision was made at the given version.
function CachedEnforcer:setCachedResult(key, res, version)
    if version ~= nil and version ~= self.cacheVersion then
        return
    end
    self.m:set(key, res)
end

function CachedEnforcer:invalidateCache()
    self.m:clear()
end

return CachedEnforcer