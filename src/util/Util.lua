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

-- Utility Functions for lua-casbin
local Util = {}

-- arrayToString convert table of strings to one string
function Util.arrayToString(rule)
    local str = ""
    if #rule>0 then str = rule[1] end
    for i = 2, #rule do
        str = str .. ", " .. rule[i]
    end
    return str
end 

--[[
    * splitCommaDelimited splits a comma-delimited string into a string array. It assumes that any
    * number of whitespace might exist before or after the comma and that tokens do not include
    * whitespace as part of their value.
    *
    * @param str the comma-delimited string.
    * @return the array with the string tokens.
]]
function Util.splitCommaDelimited(str)
    str = str .. ","
    local t ={}
    for word in str:gmatch("([^,]+),%s*") do
         table.insert(t,Util.trim(word))
    end
    return t
end

-- stringLiteralEnd returns the index just past the string literal that opens at str[i].
-- A backslash escapes the next character, as in the expression evaluator, so the
-- literal ends at the next unescaped matching quote, or at the end of str when it is
-- not closed.
function Util.stringLiteralEnd(str, i)
    local quote = string.sub(str, i, i)
    local j = i + 1
    while j <= #str do
        local c = string.sub(str, j, j)
        if c == "\\" and j < #str then
            j = j + 1
        elseif c == quote then
            return j + 1
        end
        j = j + 1
    end
    return #str + 1
end

local function escapeAssertionUnquoted(str)
    if str == "" then
        return str
    end
    str = (" " .. str):gsub("([^%w])([rp])%.", "%1%2_")
    return string.sub(str, 2)
end

--Escapes the dots in the assertion, because the expression evaluation doesn't support such variable names.
--Quoted string literals are kept as they are.
function Util.escapeAssertion(str)
    local res = {}
    local start = 1
    local i = 1
    while i <= #str do
        local c = string.sub(str, i, i)
        if c == '"' or c == "'" then
            local e = Util.stringLiteralEnd(str, i)
            table.insert(res, escapeAssertionUnquoted(string.sub(str, start, i - 1)))
            table.insert(res, string.sub(str, i, e - 1))
            start = e
            i = e
        else
            i = i + 1
        end
    end
    table.insert(res, escapeAssertionUnquoted(string.sub(str, start)))
    return table.concat(res)
end

--Removes the comments starting with # in the text.
--A # inside a quoted string literal is part of the literal.
function Util.removeComments(str)
    local i = 1
    while i <= #str do
        local c = string.sub(str, i, i)
        if c == "#" then
            str = string.sub(str, 1, i - 1)
            break
        elseif c == '"' or c == "'" then
            i = Util.stringLiteralEnd(str, i)
        else
            i = i + 1
        end
    end

    return Util.trim(str)
end

function Util.arrayEquals(a, b)
    if #a ~= #b then
        return false
    end
    for i = 1, #a do
        if a[i] ~= b[i] then
            return false
        end
    end
    return true
end

function Util.array2DEquals(a, b)
    if #a ~= #b then
        return false
    end
    for i = 1, #a do
        if not Util.arrayEquals(a[i], b[i]) then
            return false
        end
    end
    return true
end

function Util.arrayRemoveDuplications(s)
    local hash = {}
    local res = {}
    for _, v in pairs(s) do
        if not hash[v] then
            table.insert(res, v)
            hash[v] = true
        end
    end
    return res
end

-- Trims the leading and trailing whitespaces from a string
function Util.trim(s)
    return (s:gsub("^%s*(.-)%s*$", "%1"))
end

--[[
    * Splits string "str" with any "delimiter" and returns a table
    * (optional) 'x' is the maximum no. of times the string should be split
]]
function Util.split(str, delimiter, x)
    local result = {}
    local from  = 1
    local delim_from, delim_to = string.find(str, delimiter, from)
    while delim_from do
        table.insert(result, Util.trim(string.sub(str, from, delim_from-1)))
        from = delim_to + 1
        delim_from, delim_to = string.find(str, delimiter, from)
        if x~=nil then x = x - 1 end
        if x == 0 then break end
    end
    table.insert(result, Util.trim(string.sub(str, from)))
    return result
end

--[[
    * isInstance checks if o has parent as it's parent tables(metatables) recursively
    * @param base table, parent table
    * @returns true/false
]]
function Util.isInstance(o, parent)
    while o do
        o = getmetatable(o)
        if parent == o then return true end
    end
    return false
end

-- Searches if all values in a table are present in the other table regardless of order
function Util.areTablesSame(a, b)
    local c = {}
    for _, v in pairs(a) do
        if c[v] then
            c[v] = c[v] + 1
        else
            c[v] = 1
        end
    end

    for _, v in pairs(b) do
        if c[v] then
            c[v] = c[v] - 1
            if c[v] == 0 then
                c[v] = nil
            end
        else
            return false
        end
    end
    for _, v in pairs(c) do
        if v then
            return false
        end
    end
    return true
end

-- checks if the matcher string has eval(...)
function Util.hasEval(str)
    return string.find(str, "eval%((.-)%)")
end

-- finds if string has eval and replaces eval(...) with its value so that it can be evaluated by luaxp
function Util.findAndReplaceEval(str, context)
    local m = string.gsub(str, "eval%((.-)%)", function (s)
        return Util.escapeAssertion(context[Util.trim(s)])
    end)
    return m
end

local function isIdentChar(c)
    return c:match("[%w_%.]") ~= nil
end

-- matchingParen returns the index of the ")" closing the "(" at str[i], skipping quoted literals.
local function matchingParen(str, i)
    local depth = 0
    while i <= #str do
        local c = string.sub(str, i, i)
        if c == '"' or c == "'" then
            i = Util.stringLiteralEnd(str, i)
        else
            if c == "(" then
                depth = depth + 1
            elseif c == ")" then
                depth = depth - 1
                if depth == 0 then
                    return i
                end
            end
            i = i + 1
        end
    end
    return nil
end

-- splitInValues splits a list on its top-level commas, keeping quoted literals and nested calls intact.
local function splitInValues(str)
    local vals = {}
    local depth = 0
    local start = 1
    local i = 1
    while i <= #str do
        local c = string.sub(str, i, i)
        if c == '"' or c == "'" then
            i = Util.stringLiteralEnd(str, i)
        else
            if c == "(" then
                depth = depth + 1
            elseif c == ")" then
                depth = depth - 1
            elseif c == "," and depth == 0 then
                table.insert(vals, Util.trim(string.sub(str, start, i - 1)))
                start = i + 1
            end
            i = i + 1
        end
    end
    local last = Util.trim(string.sub(str, start))
    if last ~= "" or #vals > 0 then
        table.insert(vals, last)
    end
    return vals
end

-- findInOperator finds the first "operand in (...)" outside quoted literals and returns the
-- start of the operand, and the positions of the "(" and ")" around the list.
local function findInOperator(str)
    local stack = {}
    local operandStart
    local identStart, identEnd
    local i = 1
    while i <= #str do
        local c = string.sub(str, i, i)
        if c == '"' or c == "'" then
            operandStart = i
            i = Util.stringLiteralEnd(str, i)
        elseif isIdentChar(c) then
            local s = i
            while i <= #str and isIdentChar(string.sub(str, i, i)) do
                i = i + 1
            end
            if string.sub(str, s, i - 1) == "in" and operandStart then
                local j = i
                while string.sub(str, j, j):match("^%s$") do
                    j = j + 1
                end
                if string.sub(str, j, j) == "(" then
                    local close = matchingParen(str, j)
                    if close then
                        return operandStart, j, close
                    end
                end
            end
            operandStart = s
            identStart, identEnd = s, i - 1
        elseif c == "(" then
            if identEnd == i - 1 then
                table.insert(stack, identStart)
            else
                table.insert(stack, i)
            end
            operandStart = nil
            i = i + 1
        elseif c == ")" then
            operandStart = table.remove(stack)
            i = i + 1
        else
            if not c:match("%s") then
                operandStart = nil
            end
            i = i + 1
        end
    end
    return nil
end

-- replaces obj in (obj1, obj2, ...) to (obj == obj1 || obj == obj2 || ...)
-- The expansion is parenthesized so that "in" keeps binding tighter than && and ||.
function Util.replaceInOfMatcher(str)
    while true do
        local operandStart, open, close = findInOperator(str)
        if not operandStart then
            return str
        end

        local operand = Util.trim(string.sub(str, operandStart, open - 1))
        operand = Util.trim(string.sub(operand, 1, -3))
        local vals = splitInValues(string.sub(str, open + 1, close - 1))
        local terms = {}
        for _, v in ipairs(vals) do
            table.insert(terms, operand .. " == " .. v)
        end
        local expanded = "(false)"
        if #terms > 0 then
            expanded = "(" .. table.concat(terms, " || ") .. ")"
        end

        str = string.sub(str, 1, operandStart - 1) .. expanded .. string.sub(str, close + 1)
    end
end

-- returns deep (recursive) copy of a table (values only)
function Util.deepCopy(org)
    if type(org) ~= "table" then
        return org
    end
    local copy = {}
    for k, v in pairs(org) do
        copy[k] = Util.deepCopy(v)
    end
    setmetatable(copy,getmetatable(org))
    return copy
end

-- setSubtract returns the elements in `a` that aren't in `b`.
function Util.setSubtract(a, b)
    local res = {}
    for _, v in pairs(a) do
        res[v] = true
    end
    for _, v in pairs(b) do
        if res[v] then
            res[v] = nil
        else
            res[v] = true
        end
    end
    local diff = {}
    for v, chk in pairs(res) do
        if chk == true then
            table.insert(diff, v)
        end
    end

    return diff
end

-- printTable recursively prints a table for logging
function Util.printTable(t)
    local s = "{ "
    for k, v in pairs(t) do
        if type(v) == "table" then
            s = s .. Util.printTable(v) .. ", "
        else
            if type(k)=="string" then
                s = s .. k .. " = " .. v .. ", "
            else
                s = s .. v .. ", "
            end
        end
    end
    s = string.sub(s, 1, -3)
    s = s .. " }"
    return s
end

function Util.isOnlyWhitespaces(str)
    return str:match("^%s*$") ~= nil
end

function Util.splitEnhanced(str, delim, trimFields)
    local result = {}
    local i = 1
    local quotedField
    local escaping = false
    local field = ""

    if delim == nil then delim = ',' end
    if trimFields == nil then trimFields = true end
  
    -- Loop over the characters of the string
    while i <= #str do
        local char = str:sub(i, i)

        -- Check if it's the first character and it's a double quote.
        if Util.isOnlyWhitespaces(field) and char == '"' then
            -- Then this field is a quoted field
            quotedField = true
        else
            if quotedField then
                if escaping then
                    -- ", End of quoted field
                    if char == delim then
                        if trimFields then
                            field = Util.trim(field)
                        end
    
                        table.insert(result, field)
                        field = ""
                        quotedField = false
                    -- "" Escapes the double quote character
                    elseif char == '"' then
                        field = field .. char
                        escaping = false
                    -- " followed by some other character (not allowed)
                    else
                        error("Quoted fields cannot have extra characters outside double quotes.")
                    end
                else -- Not escaping
                    if char == '"' then
                        escaping = true
                    else
                        field = field .. char
                    end
                end

            else -- Not quotedField
                if char == delim then
                    if trimFields then
                        field = Util.trim(field)
                    end

                    table.insert(result, field)
                    field = ""
                else
                    field = field .. char
                end
            end
        end

        i = i + 1
    end

    -- Throw error if there are quotes left open
    if quotedField and not escaping then
        error("Unmatched quotes.")
    end
  
    -- Add the last field (since it won't have the delimiter after it)
    if trimFields then
        field = Util.trim(field)
    end
    table.insert(result, field)
  
    return result
end

return Util