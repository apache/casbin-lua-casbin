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
    * DatabaseAdapter is the SQL adapter for Casbin. It stores the policy in the
    * usual Casbin table layout (ptype, v0 .. v5) so it is compatible with the
    * tables written by casbin adapters of the other languages.
    *
    * The adapter does not talk to a database itself, it talks to a "driver":
    * any object with a query() method, which is exactly the shape of the
    * OpenResty database clients used inside APISIX.
    *
    *     driver:query(sql) -> rows, err
    *
    * A SELECT must return an array of rows, each row a table with the ptype
    * and v0 .. v5 fields. Any other statement may return anything truthy.
    * A failure is reported either by raising an error or, like the OpenResty
    * clients do, by returning nil/false plus an error message; both reach the
    * enforcer.
    *
    * Example with lua-resty-mysql:
    *
    *     local mysql = require("resty.mysql")
    *     local db = mysql:new()
    *     db:connect({host = "127.0.0.1", database = "casbin", ...})
    *
    *     local a = DatabaseAdapter:new(db, {dialect = "mysql",
    *                                        escapeLiteral = ngx.quote_sql_str})
    *     local e = Enforcer:new("model.conf", a)
    *
    * Example with pgmoon:
    *
    *     local pg = require("pgmoon").new({host = "127.0.0.1", ...})
    *     pg:connect()
    *
    *     local a = DatabaseAdapter:new(pg, {dialect = "postgres",
    *                                        escapeLiteral = function(v)
    *                                            return pg:escape_literal(v)
    *                                        end})
]]
local DatabaseAdapter = {}
setmetatable(DatabaseAdapter, Adapter)

-- The number of value columns (v0 .. v5), the Casbin standard.
local COLUMN_COUNT = 6

--[[
    * escapeAnsi quotes a value the way the SQL standard does, by doubling the
    * single quotes. It is correct for PostgreSQL and SQLite.
]]
local function escapeAnsi(value)
    return "'" .. (tostring(value):gsub("'", "''")) .. "'"
end

--[[
    * escapeMySQL quotes a value the way MySQL does, with backslash escapes.
    * MySQL treats a backslash inside a string literal as an escape character
    * unless NO_BACKSLASH_ESCAPES is set, so it must be escaped as well.
]]
local function escapeMySQL(value)
    local s = tostring(value):gsub("\\", "\\\\"):gsub("'", "\\'")
    return "'" .. s .. "'"
end

local escapers = {
    mysql = escapeMySQL,
    mariadb = escapeMySQL,
    postgres = escapeAnsi,
    postgresql = escapeAnsi,
    sqlite = escapeAnsi,
    sqlite3 = escapeAnsi,
}

local createTableSQL = {
    mysql = "CREATE TABLE IF NOT EXISTS %s (" ..
        "id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, " ..
        "ptype VARCHAR(100), v0 VARCHAR(100), v1 VARCHAR(100), v2 VARCHAR(100), " ..
        "v3 VARCHAR(100), v4 VARCHAR(100), v5 VARCHAR(100))",
    postgres = "CREATE TABLE IF NOT EXISTS %s (" ..
        "id SERIAL PRIMARY KEY, " ..
        "ptype VARCHAR(100), v0 VARCHAR(100), v1 VARCHAR(100), v2 VARCHAR(100), " ..
        "v3 VARCHAR(100), v4 VARCHAR(100), v5 VARCHAR(100))",
    sqlite = "CREATE TABLE IF NOT EXISTS %s (" ..
        "id INTEGER PRIMARY KEY AUTOINCREMENT, " ..
        "ptype TEXT, v0 TEXT, v1 TEXT, v2 TEXT, v3 TEXT, v4 TEXT, v5 TEXT)",
}
createTableSQL.mariadb = createTableSQL.mysql
createTableSQL.postgresql = createTableSQL.postgres
createTableSQL.sqlite3 = createTableSQL.sqlite

--[[
    * failed tells whether a driver reported a failure through the
    * "return nil/false, err" convention used by the OpenResty clients.
]]
local function failed(ok, err)
    return ok == false or (ok == nil and err ~= nil)
end

--[[
    * isBlank tells whether a column read back from the database carries no
    * value. Drivers spell SQL NULL differently: pgmoon omits the field, while
    * lua-resty-mysql returns the ngx.null sentinel, which is neither a string
    * nor a number. The empty string counts as blank too, because the Casbin
    * adapters of the other languages leave the unused columns empty rather
    * than NULL, and their tables have to stay readable here.
]]
local function isBlank(value)
    local t = type(value)
    if t == "number" then
        return false
    end
    return t ~= "string" or value == ""
end

--[[
    * DatabaseAdapter:new(driver, options) returns a new DatabaseAdapter.
    *
    * @param driver an object with a query(sql) method, see the notes above.
    * @param options an optional table:
    *        tableName     the policy table, "casbin_rule" by default.
    *        dialect       "mysql", "postgres" or "sqlite", "mysql" by default.
    *                      It only selects the default quoting and the DDL of
    *                      createTable().
    *        escapeLiteral function(value) returning a quoted SQL literal. Pass
    *                      the one of your driver (ngx.quote_sql_str for
    *                      lua-resty-mysql, pg:escape_literal for pgmoon) when
    *                      you can, it is always the most accurate.
    *        orderBy       column used to keep the rule order stable across
    *                      reloads, "id" by default. Set it to false if your
    *                      table has no such column.
    *        filtered      set it to true to start out filtered, so that the
    *                      enforcer does not load the whole table on creation
    *                      and waits for your loadFilteredPolicy() call.
]]
function DatabaseAdapter:new(driver, options)
    if not driver or type(driver.query) ~= "function" then
        error("DatabaseAdapter needs a driver with a query() method.")
    end

    options = options or {}

    local dialect = string.lower(options.dialect or "mysql")
    if not escapers[dialect] then
        error("Unsupported dialect: " .. tostring(options.dialect))
    end

    local o = {}
    setmetatable(o, self)
    self.__index = self

    o.driver = driver
    o.dialect = dialect
    o.tableName = options.tableName or "casbin_rule"
    o.escapeLiteral = options.escapeLiteral or escapers[dialect]
    if options.orderBy == nil then
        o.orderBy = "id"
    else
        o.orderBy = options.orderBy
    end
    o.isFiltered = options.filtered == true

    return o
end

--[[
    * exec runs a statement on the driver and normalizes the outcome, so that a
    * driver raising an error and a driver returning "nil, err" look the same
    * to the rest of the adapter.
    *
    * @param sql the statement.
    * @return the driver result on success, or false plus the error message.
]]
function DatabaseAdapter:exec(sql)
    local status, res, err = pcall(self.driver.query, self.driver, sql)

    if status == false then
        return false, tostring(res)
    end

    if failed(res, err) then
        return false, tostring(err or "unknown error")
    end

    return res
end

--[[
    * createTable creates the policy table when it does not exist yet. It is a
    * convenience for simple deployments, a schema managed elsewhere works just
    * as well.
]]
function DatabaseAdapter:createTable()
    return self:exec(string.format(createTableSQL[self.dialect], self.tableName))
end

--[[
    * rowToRule turns a database row into a policy rule. Casbin stores a rule
    * of n values in the first n columns, so the rule ends at the first column
    * that carries no value.
]]
local function rowToRule(row)
    local rule = {}
    for i = 1, COLUMN_COUNT do
        local value = row["v" .. (i - 1)]
        if isBlank(value) then
            break
        end
        table.insert(rule, tostring(value))
    end
    return rule
end

--[[
    * addRuleToModel puts a rule read from the database into the model. Rows of
    * a ptype the model does not declare are skipped, the same way the file
    * adapter skips policy lines it cannot place.
]]
local function addRuleToModel(model, ptype, rule)
    if type(ptype) ~= "string" or ptype == "" then
        return
    end

    local sec = ptype:sub(1, 1)
    if not model.model[sec] then return end
    if not model.model[sec][ptype] then return end

    model:addPolicy(sec, ptype, rule)
end

--[[
    * loadPolicy loads all policy rules from the database.
]]
function DatabaseAdapter:loadPolicy(model)
    local sql = "SELECT ptype, v0, v1, v2, v3, v4, v5 FROM " .. self.tableName
    if self.orderBy then
        sql = sql .. " ORDER BY " .. self.orderBy
    end

    local rows, err = self:exec(sql)
    if failed(rows, err) then
        return false, err
    end

    for _, row in ipairs(rows or {}) do
        addRuleToModel(model, row.ptype, rowToRule(row))
    end

    self.isFiltered = false
    return true
end

--[[
    * sectionClause builds the WHERE clause selecting the rules of one section
    * that match the filter values. An empty value matches anything, as in the
    * file adapter.
]]
function DatabaseAdapter:sectionClause(sec, values)
    -- The section letter is a literal of ours, so it needs no quoting.
    local clause = "ptype LIKE '" .. sec .. "%'"

    for i, value in ipairs(values or {}) do
        if i > COLUMN_COUNT then
            error("Filter of section " .. sec .. " has more than " .. COLUMN_COUNT .. " values.")
        end
        if value ~= "" then
            clause = clause .. " AND v" .. (i - 1) .. " = " .. self.escapeLiteral(value)
        end
    end

    return clause
end

--[[
    * loadFilteredPolicy loads only the policy rules that match the filter, so
    * that a big policy table does not have to be held in memory as a whole.
    *
    * @param model the model.
    * @param filter a table with the P and G value lists, like the filter of
    *               the file adapter. A nil filter loads everything.
]]
function DatabaseAdapter:loadFilteredPolicy(model, filter)
    if filter == nil then
        return self:loadPolicy(model)
    end

    if not filter.P or not filter.G then
        error("Invalid filter type.")
    end

    local sql = "SELECT ptype, v0, v1, v2, v3, v4, v5 FROM " .. self.tableName ..
        " WHERE (" .. self:sectionClause("p", filter.P) .. ")" ..
        " OR (" .. self:sectionClause("g", filter.G) .. ")"
    if self.orderBy then
        sql = sql .. " ORDER BY " .. self.orderBy
    end

    local rows, err = self:exec(sql)
    if failed(rows, err) then
        return false, err
    end

    for _, row in ipairs(rows or {}) do
        addRuleToModel(model, row.ptype, rowToRule(row))
    end

    self.isFiltered = true
    return true
end

--[[
    * insertValues renders the "('p', 'alice', ...)" tuple of one rule. Columns
    * the rule does not fill are stored as NULL, which is what rowToRule reads
    * back as "the rule ends here".
]]
function DatabaseAdapter:insertValues(ptype, rule)
    if #rule > COLUMN_COUNT then
        error("A policy rule cannot have more than " .. COLUMN_COUNT .. " values.")
    end

    local values = {self.escapeLiteral(ptype)}
    for i = 1, COLUMN_COUNT do
        if rule[i] == nil then
            table.insert(values, "NULL")
        else
            table.insert(values, self.escapeLiteral(rule[i]))
        end
    end

    return "(" .. table.concat(values, ", ") .. ")"
end

--[[
    * insertSQL renders an INSERT of one or more rules of the same ptype.
]]
function DatabaseAdapter:insertSQL(ptype, rules)
    local tuples = {}
    for _, rule in ipairs(rules) do
        table.insert(tuples, self:insertValues(ptype, rule))
    end

    return "INSERT INTO " .. self.tableName ..
        " (ptype, v0, v1, v2, v3, v4, v5) VALUES " .. table.concat(tuples, ", ")
end

--[[
    * ruleClause builds the WHERE clause identifying exactly one rule: the
    * columns the rule does not fill must be empty, otherwise a shorter rule
    * would also match a longer one sharing its prefix. Empty is matched as
    * both NULL and "", so that rows written by a Casbin adapter of another
    * language can be deleted here as well.
]]
function DatabaseAdapter:ruleClause(ptype, rule)
    local clause = "ptype = " .. self.escapeLiteral(ptype)

    for i = 1, COLUMN_COUNT do
        if rule[i] == nil then
            clause = clause .. " AND (v" .. (i - 1) .. " IS NULL OR v" .. (i - 1) .. " = '')"
        else
            clause = clause .. " AND v" .. (i - 1) .. " = " .. self.escapeLiteral(rule[i])
        end
    end

    return clause
end

--[[
    * savePolicy saves all policy rules to the database, replacing what is
    * stored there. Wrap the call in a transaction of your own if you need the
    * replacement to be atomic.
]]
function DatabaseAdapter:savePolicy(model)
    local ok, err = self:exec("DELETE FROM " .. self.tableName)
    if failed(ok, err) then
        return false, err
    end

    for _, sec in ipairs({"p", "g"}) do
        if model.model[sec] then
            for ptype, ast in pairs(model.model[sec]) do
                if #ast.policy > 0 then
                    ok, err = self:exec(self:insertSQL(ptype, ast.policy))
                    if failed(ok, err) then
                        return false, err
                    end
                end
            end
        end
    end

    return true
end

--[[
    * addPolicy adds a policy rule to the database.
]]
function DatabaseAdapter:addPolicy(sec, ptype, rule)
    local ok, err = self:exec(self:insertSQL(ptype, {rule}))
    if failed(ok, err) then
        return false, err
    end
    return true
end

--[[
    * addPolicies adds policy rules to the database.
]]
function DatabaseAdapter:addPolicies(sec, ptype, rules)
    if not rules or #rules == 0 then
        return true
    end

    local ok, err = self:exec(self:insertSQL(ptype, rules))
    if failed(ok, err) then
        return false, err
    end
    return true
end

--[[
    * removePolicy removes a policy rule from the database.
]]
function DatabaseAdapter:removePolicy(sec, ptype, rule)
    local ok, err = self:exec("DELETE FROM " .. self.tableName ..
        " WHERE " .. self:ruleClause(ptype, rule))
    if failed(ok, err) then
        return false, err
    end
    return true
end

--[[
    * removePolicies removes policy rules from the database.
]]
function DatabaseAdapter:removePolicies(sec, ptype, rules)
    for _, rule in ipairs(rules or {}) do
        local ok, err = self:removePolicy(sec, ptype, rule)
        if failed(ok, err) then
            return false, err
        end
    end
    return true
end

--[[
    * filteredClause builds the WHERE clause of removeFilteredPolicy. As
    * everywhere in Casbin, fieldIndex is zero based: 0 stands for column v0.
]]
function DatabaseAdapter:filteredClause(ptype, fieldIndex, fieldValues)
    if fieldIndex < 0 or fieldIndex + #fieldValues > COLUMN_COUNT then
        error("The field index is out of range.")
    end

    local clause = "ptype = " .. self.escapeLiteral(ptype)

    for i, value in ipairs(fieldValues) do
        if value ~= "" then
            clause = clause .. " AND v" .. (fieldIndex + i - 1) .. " = " .. self.escapeLiteral(value)
        end
    end

    return clause
end

--[[
    * removeFilteredPolicy removes the policy rules that match the filter from
    * the database.
]]
function DatabaseAdapter:removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues)
    local ok, err = self:exec("DELETE FROM " .. self.tableName ..
        " WHERE " .. self:filteredClause(ptype, fieldIndex, fieldValues))
    if failed(ok, err) then
        return false, err
    end
    return true
end

--[[
    * updatePolicy replaces a policy rule in the database.
]]
function DatabaseAdapter:updatePolicy(sec, ptype, oldRule, newRule)
    local ok, err = self:removePolicy(sec, ptype, oldRule)
    if failed(ok, err) then
        return false, err
    end

    return self:addPolicy(sec, ptype, newRule)
end

--[[
    * updatePolicies replaces several policy rules in the database.
]]
function DatabaseAdapter:updatePolicies(sec, ptype, oldRules, newRules)
    local ok, err = self:removePolicies(sec, ptype, oldRules)
    if failed(ok, err) then
        return false, err
    end

    return self:addPolicies(sec, ptype, newRules)
end

--[[
    * updateFilteredPolicies deletes the rules matching the filter and adds the
    * new rules in their place.
]]
function DatabaseAdapter:updateFilteredPolicies(sec, ptype, newRules, fieldIndex, fieldValues)
    local ok, err = self:removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues)
    if failed(ok, err) then
        return false, err
    end

    return self:addPolicies(sec, ptype, newRules)
end

return DatabaseAdapter
