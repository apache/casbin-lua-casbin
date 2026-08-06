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

local rex = require ("rex_pcre2")
local posix = require("posix.fnmatch")

local BuiltInFunctions = {}

function BuiltInFunctions.validateVariadicArgs(expectedLen, args)
    if #args ~= expectedLen then
        return error("Expected "..expectedLen.." arguments, but got "..#args)
    end
    for i=1,expectedLen do
        if type(args[i])~="string" then
            return error("Argument must be a string")
        end
    end
end

-- KeyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
-- For example, "/foo/bar" matches "/foo/*"
function BuiltInFunctions.keyMatch(key1, key2)
    local i, _ = string.find(key2, "*")

    if not i then
        return (key1 == key2)
    end

    if #key1>=i then
        return (string.sub(key1, 1, i-1) == string.sub(key2, 1, i-1))
    end
    return (key1 == string.sub(key2, 1, i-1))
end

-- Wrapper for keyMatch
function BuiltInFunctions.keyMatchFunc(args)
    BuiltInFunctions.validateVariadicArgs(2, args)
    return BuiltInFunctions.keyMatch(args[1], args[2])
end

-- KeyGet returns the matched part
-- For example, "/foo/bar/foo" matches "/foo/*"
-- "bar/foo" will been returned
function BuiltInFunctions.keyGet(key1, key2)
    local i, _ = string.find(key2, "*")

    if not i then
        return ""
    end
    if #key1>=i then
        if string.sub(key1, 1, i-1) == string.sub(key2, 1, i-1)  then
            return string.sub(key1, i)
        end
    end
    return ""
end

-- Wrapper for keyGet
function BuiltInFunctions.keyGetFunc(args)
    BuiltInFunctions.validateVariadicArgs(2, args)
    return BuiltInFunctions.keyGet(args[1], args[2])
end

-- KeyMatch2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
-- For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
function BuiltInFunctions.keyMatch2(key1, key2)
    key2 = string.gsub(key2, "/%*", "/.*")
    if key2 == "*" then key2 = ".*" end
    local key = rex.gsub(key2, ":[^/]+", "[^/]+")
	return BuiltInFunctions.regexMatch(key1, "^"..key.."$")
end

-- Wrapper for keyMatch2
function BuiltInFunctions.keyMatch2Func(args)
    BuiltInFunctions.validateVariadicArgs(2, args)
    return BuiltInFunctions.keyMatch2(args[1], args[2])
end

-- KeyGet2 returns value matched pattern
-- For example, "/resource1" matches "/:resource"
-- if the pathVar == "resource", then "resource1" will be returned
function BuiltInFunctions.keyGet2(key1, key2 , pathVar)
    key2 = string.gsub(key2, "/%*", "/.*")
    local keys ={}
    local repl=function(s)
        table.insert(keys, string.sub(s, 1, -1))
        return "([^/]+)"
    end
    key2 = string.gsub(key2,":[^/]+",repl)
    key2 = "^" .. key2 .. "$"
    local values = {string.match(key1,key2)}
    if #values == 0 then
        return ""
    end
    for i, key in pairs(keys) do
        if pathVar == string.sub(key,2,-1) then
            return values[i]
        end
    end
    return ""
end

-- Wrapper for KeyGet2
function BuiltInFunctions.keyGet2Func(args)
    BuiltInFunctions.validateVariadicArgs(3, args)
    return BuiltInFunctions.keyGet2(args[1], args[2],args[3])
end

-- KeyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
-- For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
function BuiltInFunctions.keyMatch3(key1, key2)
    key2 = string.gsub(key2, "/%*", "/.*")
    local key = rex.gsub(key2, "{[^/]+}", "[^/]+")
	return BuiltInFunctions.regexMatch(key1, "^"..key.."$")
end

-- Wrapper for keyMatch3
function BuiltInFunctions.keyMatch3Func(args)
    BuiltInFunctions.validateVariadicArgs(2, args)
    return BuiltInFunctions.keyMatch3(args[1], args[2])
end

-- KeyMatch4 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
-- Besides what KeyMatch3 does, KeyMatch4 can also match repeated patterns:
-- "/parent/123/child/123" matches "/parent/{id}/child/{id}"
-- "/parent/123/child/456" does not match "/parent/{id}/child/{id}"
-- But KeyMatch3 will match both.
function BuiltInFunctions.keyMatch4(key1, key2)
    key2 = string.gsub(key2, "/%*", "/.*")
    local tokens={}
    local repl=function(s)
        table.insert(tokens, string.sub(s, 1, -1))
        return "([^/]+)"
    end
    key2=string.gsub(key2,"{([^/]+)}",repl)
    key2="^" .. key2 .. "$"

    -- Without any {token}, the pattern has no captures, so string.match would
    -- return the whole match instead of a (possibly empty) list of values.
    if #tokens==0 then
        return string.match(key1, key2)~=nil
    end

    local matches={string.match(key1, key2)}
    if matches[1]==nil then
        return false
    end
    if #tokens~= #matches then
        error("KeyMatch4: number of tokens is not equal to number of values")
    end
    local values={}
    for key, token in pairs(tokens) do
        if values[token]==nil then
            values[token] = matches[key]
        end
        if values[token] ~= matches[key] then
            return false
        end
    end

    return true
end

-- Wrapper for keyMatch4
function BuiltInFunctions.keyMatch4Func(args)
    BuiltInFunctions.validateVariadicArgs(2, args)
    return BuiltInFunctions.keyMatch4(args[1], args[2])
end

-- KeyMatch5 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *
-- For example,
-- - "/foo/bar?status=1&type=2" matches "/foo/bar"
-- - "/parent/child1" and "/parent/child1" matches "/parent/*"
-- - "/parent/child1?status=1" matches "/parent/*"
function BuiltInFunctions.keyMatch5(key1, key2)
    local i = string.find(key1, "?", 1, true)

    if i then
        key1 = string.sub(key1, 1, i - 1)
    end

    key2 = string.gsub(key2, "/%*", "/.*")
    key2 = string.gsub(key2, "%{[^/]+%}", "[^/]+")

    return string.match(key1, "^" .. key2 .. "$") ~= nil
end

-- Wrapper for keyMatch5
function BuiltInFunctions.keyMatch5Func(args)
    BuiltInFunctions.validateVariadicArgs(2, args)
    return BuiltInFunctions.keyMatch5(args[1], args[2])
end

-- RegexMatch determines whether key1 matches the pattern of key2 in regular expression.
function BuiltInFunctions.regexMatch(key1, key2)
    local res = rex.match(key1, key2)
    if res then
        return true
    else
        return false
    end
end

-- Wrapper for regexMatch
function BuiltInFunctions.regexMatchFunc(args)
    BuiltInFunctions.validateVariadicArgs(2, args)
    return BuiltInFunctions.regexMatch(args[1], args[2])
end

-- IPMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
-- For example, "192.168.2.123" matches "192.168.2.0/24"
function BuiltInFunctions.IPMatch(ip1, ip2)
    local getip1 = {string.match(ip1,"(%d+)%.(%d+)%.(%d+)%.(%d+)" )}
    local objIP1=0
    for i=1,4 do
        if getip1[i]==nil or tonumber(getip1[i])>255 or tonumber(getip1[i])<0 then
            error("invalid argument: ip1 in IPMatch() function is not an IP address.")
        else
            objIP1=objIP1+2^(8*(4-i))*getip1[i]
        end
    end
    if ip1==ip2 then
        return true
    end

    local cidr
    ip2=string.gsub(ip2,"/(%d+)",function(s) cidr=s return "" end)
    local getip2 = {string.match(ip2,"(%d+)%.(%d+)%.(%d+)%.(%d+)" )}
    local objIP2=0
    for i=1,4 do
        if getip2[i]==nil or tonumber(getip2[i])>255 or tonumber(getip2[i])<0 then
            error("invalid argument: ip1 in IPMatch() function is not an IP address.")
        else
            objIP2=objIP2+2^(8*(4-i))*getip2[i]
        end
    end
    if cidr==nil then
        return false
    else
        local number1,_=math.modf(objIP1/(2^(32-cidr)))
        local number2,_=math.modf(objIP2/(2^(32-cidr)))
        if number1~=number2 then
            return false
        else
            return true
        end
    end
end

-- Wrapper for IPMatch.
function BuiltInFunctions.IPMatchFunc(args)
    BuiltInFunctions.validateVariadicArgs(2, args)
    return BuiltInFunctions.IPMatch(args[1], args[2])
end

-- GlobMatch determines whether key1 matches the pattern of key2 using glob pattern
function BuiltInFunctions.globMatch(key1, key2)
    if posix.fnmatch(key2, key1, posix.FNM_PATHNAME or posix.FNM_PERIOD) == 0 then
        return true
    else
        return false
    end
end

-- Wrapper for globMatch
function BuiltInFunctions.globMatchFunc(args)
    BuiltInFunctions.validateVariadicArgs(2, args)
    return BuiltInFunctions.globMatch(args[1], args[2])
end

-- GenerateGFunction is the factory method of the g(_, _) function.
function BuiltInFunctions.generateGFunction(rm)
    local function f(args)
        local name1 = args[1]
        local name2 = args[2]

        if not rm then
            return name1 == name2
        elseif #args==2 then
            return rm:hasLink(name1, name2)
        else
            local domain = args[3]
            return rm:hasLink(name1, name2, domain)
        end
    end

    return f
end

return BuiltInFunctions