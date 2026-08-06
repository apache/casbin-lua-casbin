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

local DatabaseAdapter = require("src.persist.database_adapter.DatabaseAdapter")
local Enforcer = require("src.main.Enforcer")

local path = os.getenv("PWD") or io.popen("cd"):read()
local basic_model = path .. "/examples/basic_model.conf"
local rbac_model = path .. "/examples/rbac_model.conf"

-- ngx.null stands in for the sentinel lua-resty-mysql returns for a SQL NULL:
-- a value that is neither a string nor a number.
local NULL = setmetatable({}, {__tostring = function () return "null" end})

--[[
    * FakeDriver is a database client that records the statements it is given
    * and replays canned rows, so the generated SQL can be asserted on without
    * a database.
    *
    * @param options rows  the rows a SELECT returns.
    *                fail  an error message the driver reports for every query.
    *                raise an error message the driver raises for every query.
]]
local function FakeDriver(options)
    options = options or {}

    local d = {statements = {}}

    function d:query(sql)
        table.insert(self.statements, sql)

        if options.raise then
            error(options.raise)
        end
        if options.fail then
            return nil, options.fail
        end
        if string.sub(sql, 1, 6) == "SELECT" then
            return options.rows or {}
        end
        return {affected_rows = 1}
    end

    function d:lastStatement()
        return self.statements[#self.statements]
    end

    return d
end

local basicRows = {
    {ptype = "p", v0 = "alice", v1 = "data1", v2 = "read", v3 = NULL, v4 = NULL, v5 = NULL},
    {ptype = "p", v0 = "bob", v1 = "data2", v2 = "write", v3 = NULL, v4 = NULL, v5 = NULL},
}

describe("database adapter tests", function ()

    it("test loadPolicy feeds the model", function ()
        local d = FakeDriver({rows = basicRows})
        local e = Enforcer:new(basic_model, DatabaseAdapter:new(d))

        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.True(e:enforce("bob", "data2", "write"))
        assert.is.False(e:enforce("alice", "data2", "read"))

        assert.are.equals(
            "SELECT ptype, v0, v1, v2, v3, v4, v5 FROM casbin_rule ORDER BY id",
            d.statements[1])
    end)

    it("test loadPolicy loads the g rules too", function ()
        local d = FakeDriver({rows = {
            {ptype = "p", v0 = "data2_admin", v1 = "data2", v2 = "read"},
            {ptype = "g", v0 = "alice", v1 = "data2_admin"},
        }})
        local e = Enforcer:new(rbac_model, DatabaseAdapter:new(d))

        assert.is.True(e:enforce("alice", "data2", "read"))
    end)

    -- Tables written by a Casbin adapter of another language leave the unused
    -- columns empty instead of NULL, and must read back as the same rules.
    it("test empty columns end the rule just like NULL", function ()
        local d = FakeDriver({rows = {
            {ptype = "p", v0 = "alice", v1 = "data1", v2 = "read", v3 = "", v4 = "", v5 = ""},
        }})
        local e = Enforcer:new(basic_model, DatabaseAdapter:new(d))

        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.are.same({{"alice", "data1", "read"}}, e:GetPolicy())
    end)

    it("test rows of an unknown ptype are skipped", function ()
        local d = FakeDriver({rows = {
            {ptype = "p", v0 = "alice", v1 = "data1", v2 = "read"},
            {ptype = "p2", v0 = "carol", v1 = "data9", v2 = "read"},
            {ptype = "", v0 = "dave"},
        }})
        local e = Enforcer:new(basic_model, DatabaseAdapter:new(d))

        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.are.equals(1, #e:GetPolicy())
    end)

    it("test a custom table name and no ordering column", function ()
        local d = FakeDriver({rows = basicRows})
        Enforcer:new(basic_model, DatabaseAdapter:new(d, {tableName = "acl", orderBy = false}))

        assert.are.equals("SELECT ptype, v0, v1, v2, v3, v4, v5 FROM acl", d.statements[1])
    end)

    it("test addPolicy writes an INSERT with NULL for the unused columns", function ()
        local d = FakeDriver({rows = {}})
        local e = Enforcer:new(basic_model, DatabaseAdapter:new(d))

        assert.is.True(e:AddPolicy("alice", "data1", "read"))
        assert.are.equals(
            "INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES " ..
            "('p', 'alice', 'data1', 'read', NULL, NULL, NULL)",
            d:lastStatement())
    end)

    it("test addPolicies writes a single INSERT", function ()
        local d = FakeDriver({rows = {}})
        local e = Enforcer:new(basic_model, DatabaseAdapter:new(d))

        assert.is.True(e:AddPolicies({{"alice", "data1", "read"}, {"bob", "data2", "write"}}))
        assert.are.equals(
            "INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES " ..
            "('p', 'alice', 'data1', 'read', NULL, NULL, NULL), " ..
            "('p', 'bob', 'data2', 'write', NULL, NULL, NULL)",
            d:lastStatement())
    end)

    -- A shorter rule must not match a longer one sharing its prefix, so the
    -- columns it does not fill are matched as empty. Other Casbin adapters
    -- write "" there instead of NULL, hence both spellings.
    it("test removePolicy pins the unused columns to empty", function ()
        local d = FakeDriver({rows = basicRows})
        local e = Enforcer:new(basic_model, DatabaseAdapter:new(d))

        assert.is.True(e:RemovePolicy("alice", "data1", "read"))
        assert.are.equals(
            "DELETE FROM casbin_rule WHERE ptype = 'p' AND v0 = 'alice' AND v1 = 'data1'" ..
            " AND v2 = 'read' AND (v3 IS NULL OR v3 = '') AND (v4 IS NULL OR v4 = '')" ..
            " AND (v5 IS NULL OR v5 = '')",
            d:lastStatement())
    end)

    it("test removeFilteredPolicy reads fieldIndex as zero based", function ()
        local d = FakeDriver({rows = basicRows})
        local e = Enforcer:new(basic_model, DatabaseAdapter:new(d))

        assert.is.True(e:RemoveFilteredPolicy(1, "data1", "read"))
        assert.are.equals(
            "DELETE FROM casbin_rule WHERE ptype = 'p' AND v1 = 'data1' AND v2 = 'read'",
            d:lastStatement())
    end)

    it("test removeFilteredPolicy skips the empty field values", function ()
        local d = FakeDriver({rows = basicRows})
        local a = DatabaseAdapter:new(d)

        assert.is.True(a:removeFilteredPolicy("p", "p", 0, {"alice", "", "read"}))
        assert.are.equals(
            "DELETE FROM casbin_rule WHERE ptype = 'p' AND v0 = 'alice' AND v2 = 'read'",
            d:lastStatement())
    end)

    it("test a field index out of range is rejected", function ()
        local a = DatabaseAdapter:new(FakeDriver())

        assert.is.False(pcall(function ()
            a:removeFilteredPolicy("p", "p", 4, {"a", "b", "c"})
        end))
    end)

    it("test savePolicy replaces the stored policy", function ()
        local d = FakeDriver({rows = basicRows})
        local e = Enforcer:new(basic_model, DatabaseAdapter:new(d))

        e:savePolicy()

        assert.are.equals("DELETE FROM casbin_rule", d.statements[2])
        assert.are.equals(
            "INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES " ..
            "('p', 'alice', 'data1', 'read', NULL, NULL, NULL), " ..
            "('p', 'bob', 'data2', 'write', NULL, NULL, NULL)",
            d.statements[3])
    end)

    it("test updatePolicy deletes then inserts", function ()
        local d = FakeDriver({rows = basicRows})
        local a = DatabaseAdapter:new(d)

        assert.is.True(a:updatePolicy("p", "p", {"alice", "data1", "read"}, {"alice", "data1", "write"}))
        assert.are.equals(
            "INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES " ..
            "('p', 'alice', 'data1', 'write', NULL, NULL, NULL)",
            d:lastStatement())
    end)

    it("test createTable per dialect", function ()
        for _, dialect in ipairs({"mysql", "postgres", "sqlite"}) do
            local d = FakeDriver()
            DatabaseAdapter:new(d, {dialect = dialect}):createTable()
            assert.is.truthy(string.find(d:lastStatement(),
                "CREATE TABLE IF NOT EXISTS casbin_rule", 1, true))
        end
    end)

    it("test an unsupported dialect is rejected", function ()
        assert.is.False(pcall(function ()
            DatabaseAdapter:new(FakeDriver(), {dialect = "oracle"})
        end))
    end)

    it("test a driver without query() is rejected", function ()
        assert.is.False(pcall(function () DatabaseAdapter:new({}) end))
    end)
end)

describe("database adapter quoting tests", function ()

    it("test the mysql quoting escapes quotes and backslashes", function ()
        local d = FakeDriver()
        local a = DatabaseAdapter:new(d, {dialect = "mysql"})

        a:addPolicy("p", "p", {"o'brien", "c:\\data"})

        assert.are.equals(
            "INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES " ..
            "('p', 'o\\'brien', 'c:\\\\data', NULL, NULL, NULL, NULL)",
            d:lastStatement())
    end)

    -- PostgreSQL keeps a backslash literal, doubling it would corrupt the data.
    it("test the postgres quoting only doubles the quotes", function ()
        local d = FakeDriver()
        local a = DatabaseAdapter:new(d, {dialect = "postgres"})

        a:addPolicy("p", "p", {"o'brien", "c:\\data"})

        assert.are.equals(
            "INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES " ..
            "('p', 'o''brien', 'c:\\data', NULL, NULL, NULL, NULL)",
            d:lastStatement())
    end)

    it("test the driver quoting can be used instead", function ()
        local d = FakeDriver()
        local a = DatabaseAdapter:new(d, {escapeLiteral = function (v)
            return "$$" .. v .. "$$"
        end})

        a:addPolicy("p", "p", {"alice"})

        assert.are.equals(
            "INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5) VALUES " ..
            "($$p$$, $$alice$$, NULL, NULL, NULL, NULL, NULL)",
            d:lastStatement())
    end)

    -- A rule value must never be able to break out of its literal.
    it("test an injection attempt stays inside the literal", function ()
        local d = FakeDriver()
        local a = DatabaseAdapter:new(d, {dialect = "postgres"})

        a:removePolicy("p", "p", {"alice'; DROP TABLE casbin_rule; --"})

        assert.are.equals(
            "DELETE FROM casbin_rule WHERE ptype = 'p'" ..
            " AND v0 = 'alice''; DROP TABLE casbin_rule; --'" ..
            " AND (v1 IS NULL OR v1 = '') AND (v2 IS NULL OR v2 = '')" ..
            " AND (v3 IS NULL OR v3 = '') AND (v4 IS NULL OR v4 = '')" ..
            " AND (v5 IS NULL OR v5 = '')",
            d:lastStatement())
    end)
end)

describe("database adapter filtered tests", function ()

    it("test a filtered adapter does not load on creation", function ()
        local d = FakeDriver({rows = basicRows})
        local a = DatabaseAdapter:new(d, {filtered = true})
        local e = Enforcer:new(basic_model, a)

        assert.are.equals(0, #d.statements)
        assert.is.True(e:isFiltered())
    end)

    it("test loadFilteredPolicy filters in SQL", function ()
        local d = FakeDriver({rows = {
            {ptype = "p", v0 = "alice", v1 = "data1", v2 = "read"},
        }})
        local a = DatabaseAdapter:new(d, {filtered = true})
        local e = Enforcer:new(basic_model, a)

        e:loadFilteredPolicy({P = {"alice"}, G = {"alice"}})

        assert.are.equals(
            "SELECT ptype, v0, v1, v2, v3, v4, v5 FROM casbin_rule" ..
            " WHERE (ptype LIKE 'p%' AND v0 = 'alice')" ..
            " OR (ptype LIKE 'g%' AND v0 = 'alice') ORDER BY id",
            d:lastStatement())

        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.True(e:isFiltered())
    end)

    it("test a nil filter loads everything and clears the filtered flag", function ()
        local d = FakeDriver({rows = basicRows})
        local a = DatabaseAdapter:new(d, {filtered = true})
        local e = Enforcer:new(basic_model, a)

        e:loadFilteredPolicy(nil)

        assert.is.False(e:isFiltered())
        assert.is.True(e:enforce("bob", "data2", "write"))
    end)

    it("test an invalid filter is rejected", function ()
        local a = DatabaseAdapter:new(FakeDriver(), {filtered = true})

        assert.is.False(pcall(function () a:loadFilteredPolicy({}, {P = {"alice"}}) end))
    end)
end)

describe("database adapter error tests", function ()

    it("test a driver failure on load reaches the caller", function ()
        local ok, err = pcall(function ()
            Enforcer:new(basic_model, DatabaseAdapter:new(FakeDriver({fail = "connection refused"})))
        end)

        assert.is.False(ok)
        assert.is.truthy(string.find(err, "connection refused", 1, true))
    end)

    it("test a driver raising an error reaches the caller", function ()
        local ok, err = pcall(function ()
            Enforcer:new(basic_model, DatabaseAdapter:new(FakeDriver({raise = "socket timeout"})))
        end)

        assert.is.False(ok)
        assert.is.truthy(string.find(err, "socket timeout", 1, true))
    end)

    it("test a rejected write is not applied to the model", function ()
        local d = FakeDriver({rows = {}})
        local a = DatabaseAdapter:new(d)
        local e = Enforcer:new(basic_model, a)

        a.driver = FakeDriver({fail = "duplicate key value violates unique constraint"})

        local ok, err = e:AddPolicy("alice", "data1", "read")

        assert.is.False(ok)
        assert.is.truthy(string.find(err, "duplicate key value", 1, true))
        assert.is.False(e:HasPolicy("alice", "data1", "read"))
    end)

    it("test a failed savePolicy does not insert anything", function ()
        local d = FakeDriver({rows = basicRows})
        local a = DatabaseAdapter:new(d)
        local e = Enforcer:new(basic_model, a)

        a.driver = FakeDriver({fail = "the database is read only"})

        local ok, err = pcall(function () e:savePolicy() end)

        assert.is.False(ok)
        assert.is.truthy(string.find(err, "the database is read only", 1, true))
        assert.are.equals(1, #a.driver.statements)
    end)
end)

describe("adapter isFiltered interface tests", function ()

    -- Adapters written against the FilteredAdapter interface expose isFiltered
    -- as a method. The enforcer must call it instead of reading the function
    -- itself as a truthy flag, which used to leave the policy empty.
    it("test an adapter exposing isFiltered as a method still gets loaded", function ()
        local a = DatabaseAdapter:new(FakeDriver({rows = basicRows}))
        a.isFiltered = function (self) return false end

        local e = Enforcer:new(basic_model, a)

        assert.is.False(e:isFiltered())
        assert.is.True(e:enforce("alice", "data1", "read"))
    end)

    it("test an adapter reporting itself filtered is not loaded", function ()
        local d = FakeDriver({rows = basicRows})
        local a = DatabaseAdapter:new(d)
        a.isFiltered = function (self) return true end

        local e = Enforcer:new(basic_model, a)

        assert.are.equals(0, #d.statements)
        assert.is.True(e:isFiltered())
    end)
end)
