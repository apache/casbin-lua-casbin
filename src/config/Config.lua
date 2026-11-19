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
local Util = require("src/util/Util")

local Config = {
    DEFAULT_SECTION = "default",
    DEFAULT_COMMENT = "#",
    DEFAULT_COMMENT_SEM = ";",
    DEFAULT_MULTI_LINE_SEPARATOR = "\\\\", -- This is equivalent to "\\" in the text since "\" is a special character in Lua
}

--[[
    * newConfig create an empty configuration representation from file.
    *
    * @param confName the path of the model file.
    * @return the constructor of Config.
]]
function Config:newConfig(confName)
    local c = {}
    setmetatable(c,self)
    self.__index = self
    c.data = {}
    c:parse(confName)
    return c
end

--[[
    * newConfigFromText create an empty configuration representation from text.
    *
    * @param text the model text.
    * @return the constructor of Config.
]]
function Config:newConfigFromText(text)
   	local c = {}
	setmetatable(c,self)
	self.__index = self
	c.data = {}
	local lines = {}
	string.gsub(text, '[^'.."\r\n"..']+', function(w) table.insert(lines, w) end )
	c:parseBuffer(lines)
	return c
end

-- addConfig adds a new section->key:value to the configuration.
function Config:addConfig(section, option, value)
    if section == "" then section = self.DEFAULT_SECTION end

    if self.data[section] == nil then
        self.data[section] = {}
    end

    self.data[section][option] = value
end

function Config:parse(fname)
    local lines = {}
    local f = assert(io.open(fname,"r"))

    if f then
        for line in f:lines() do
            table.insert(lines, line)
        end
    end

    f:close()
    self:parseBuffer(lines)
end

function Config:parseBuffer(lines)
    local section = ""
    local buf = {}
    local lineNum = 0
    local canWrite = false
	local line

    while true do
        if canWrite then
            if self:write(section, lineNum, buf) == true then
                buf = {}
            end
            canWrite = false
        end
        lineNum = lineNum + 1

        line = lines[lineNum]

        if lineNum>#lines then
            if #buf>0 then
                self:write(section, lineNum, buf)
            end
            break
        end

        line = Util.trim(line)

        if line == "" or self.DEFAULT_COMMENT == string.sub(line, 1, 1) or self.DEFAULT_COMMENT_SEM == string.sub(line, 1, 1) then
            canWrite = true
        elseif "[" == string.sub(line, 1, 1) and "]" == string.sub(line, -1, -1) then
            if #buf>0 then
                if self:write(section, lineNum, buf) == true then
                    buf = {}
                end
            end

            section = string.sub(line, 2, -2)
        else
            local p

            if self.DEFAULT_MULTI_LINE_SEPARATOR == string.sub(line, -2, -1) then
                p = Util.trim(string.sub(line, 1, -3))
                p = p .. " "
            else
                p = line
                canWrite = true
            end
        table.insert(buf, p)
        end
    end
end

function Config:write(section, lineNum, b)
    local buf = ""
    for _, v in pairs(b) do
        buf = buf .. v
    end

    if buf == "" then return end

    local optionVal = Util.split(buf, "=", 1)

    if #optionVal~=2 then
        error("parse the content error : line "..lineNum.." , "..optionVal[1].." = ?")
    end

    local option = Util.trim(optionVal[1])
    local value = Util.trim(optionVal[2])

    self:addConfig(section, option, value)
    return true
end

-- getBool lookups up the value using the provided key and converts the value to a bool
function Config:getBool(key)
    local s = self:get(key)
    if string.upper(s) == "TRUE" then
        return true
    elseif string.upper(s) == "FALSE" then
        return false
    else
        error("Not a boolean value")
    end
end

-- getNum lookups up the value using the provided key and converts the value to a number
function Config:getNum(key)
    local s = self:get(key)
    if tonumber(s) then
        return tonumber(s)
    else
        error("Not a num value")
    end
end

-- getString lookups up the value using the provided key and converts the value to a string
function Config:getString(key)
    return self:get(key)
end

--[[
    Strings lookups up the value using the provided key and converts the value to an array
    of string by splitting the string by comma.
]]
function Config:getStrings(key)
    local s = self:get(key)
    if s == "" then return end
    local v = Util.split(s, ",")

    return v
end

-- Set sets the value for the specific key in the Config
function Config:set(key, value)
    if #key == 0 then
        error("key is empty")
    end

    local section = ""
    local option

    local keys = Util.split(string.lower(key), "::")
    if #keys >= 2 then
        section = keys[1]
        option = keys[2]
    else
        option = keys[1]
    end

    self:addConfig(section, option, value)
end

-- section.key or key
function Config:get(key)
    local section = self.DEFAULT_SECTION
    local option

    local keys = Util.split(string.lower(key), "::")
    if #keys >= 2 then
        section = keys[1]
        option = keys[2]
    else
        option = keys[1]
    end

    if self.data[section] == nil then
        return ""
    elseif self.data[section][option] == nil then
        return ""
    else
        return self.data[section][option]
    end
end

return Config