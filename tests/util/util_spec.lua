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

local Util = require("src.util.Util")

describe("util tests", function()

    it("test arrayToString", function()
        assert.are.equals(Util.arrayToString({"data", "data1", "data2", "data3"}), "data, data1, data2, data3")
    end)

    it("test splitCommaDelimited", function()
        assert.are.same(Util.splitCommaDelimited("a,b,c"), {"a", "b", "c"})
        assert.are.same(Util.splitCommaDelimited("a, b, c"), {"a", "b", "c"})
        assert.are.same(Util.splitCommaDelimited("a ,b ,c"), {"a", "b", "c"})
        assert.are.same(Util.splitCommaDelimited("  a,     b   ,c     "), {"a", "b", "c"})
    end)

    it("test escapeAssertion", function()
        assert.are.equals("r_attr.value == p_attr",Util.escapeAssertion("r.attr.value == p.attr"))
        assert.are.equals("r_attp.value || p_attr",Util.escapeAssertion("r.attp.value || p.attr"))
        assert.are.equals("r_attp.value &&p_attr",Util.escapeAssertion("r.attp.value &&p.attr"))
        assert.are.equals("r_attp.value >p_attr",Util.escapeAssertion("r.attp.value >p.attr"))
        assert.are.equals("r_attp.value <p_attr",Util.escapeAssertion("r.attp.value <p.attr"))
        assert.are.equals("r_attp.value -p_attr",Util.escapeAssertion("r.attp.value -p.attr"))
        assert.are.equals("r_attp.value +p_attr",Util.escapeAssertion("r.attp.value +p.attr"))
        assert.are.equals("r_attp.value *p_attr",Util.escapeAssertion("r.attp.value *p.attr"))
        assert.are.equals("r_attp.value /p_attr",Util.escapeAssertion("r.attp.value /p.attr"))
        assert.are.equals("!r_attp.value /p_attr",Util.escapeAssertion("!r.attp.value /p.attr"))
        assert.are.equals("g(r_sub, p_sub) == p_attr",Util.escapeAssertion("g(r.sub, p.sub) == p.attr"))
        assert.are.equals("g(r_sub,p_sub) == p_attr",Util.escapeAssertion("g(r.sub,p.sub) == p.attr"))
        assert.are.equals("(r_attp.value || p_attr)p_u",Util.escapeAssertion("(r.attp.value || p.attr)p.u"))
        assert.are.equals("r_sub == 'p.sub' && r_obj == p_obj",Util.escapeAssertion("r.sub == 'p.sub' && r.obj == p.obj"))
        assert.are.equals('r_sub == "a r.b" || p_sub == "p.c"',Util.escapeAssertion('r.sub == "a r.b" || p.sub == "p.c"'))
        assert.are.equals("r_sub == 'it''s r.x' && p_act == p_act",Util.escapeAssertion("r.sub == 'it''s r.x' && p.act == p.act"))
        assert.are.equals("r_sub == 'a\\'p.b' && p_obj == 'p.x'",Util.escapeAssertion("r.sub == 'a\\'p.b' && p.obj == 'p.x'"))
        assert.are.equals("r_sub == 'r.x",Util.escapeAssertion("r.sub == 'r.x"))
        assert.are.equals("regexMatch(r_obj, '^/a.b$')",Util.escapeAssertion("regexMatch(r.obj, '^/a.b$')"))
    end)

    it("test removeComments", function()
        assert.are.equals("r.act == p.act", Util.removeComments("r.act == p.act # comments"))
        assert.are.equals("r.act == p.act", Util.removeComments("r.act == p.act#comments"))
        assert.are.equals("r.act == p.act", Util.removeComments("r.act == p.act###"))
        assert.are.equals("", Util.removeComments("### comments"))
        assert.are.equals("r.act == p.act", Util.removeComments("r.act == p.act"))
        assert.are.equals("r.obj == 'a#b'", Util.removeComments("r.obj == 'a#b' # comments"))
        assert.are.equals('r.obj == "#x" && r.act == p.act', Util.removeComments('r.obj == "#x" && r.act == p.act#c'))
        assert.are.equals("r.obj == 'a#b", Util.removeComments("r.obj == 'a#b"))
        assert.are.equals("r.obj == 'a\\'#b'", Util.removeComments("r.obj == 'a\\'#b' # comments"))
    end)

    it("test arrayEquals", function()
        assert.is.True(Util.arrayEquals({"a", "b", "c"},{"a", "b", "c"}), true)
        assert.is.False(Util.arrayEquals({"a", "b", "c"},{"a", "b"}), false)
        assert.is.False(Util.arrayEquals({"a", "b", "c"},{"a", "c", "b"}), false)
        assert.is.False(Util.arrayEquals({"a", "b", "c"},{}), false)
    end)

    it("test array2DEquals", function()
        assert.is.True(Util.array2DEquals({{"a", "b", "c"}, {"1", "2", "3"}},{{"a", "b", "c"}, {"1", "2", "3"}}), true)
        assert.is.False(Util.array2DEquals({{"a", "b", "c"}, {"1", "2", "3"}}, {{"a", "b", "c"}}), false)
        assert.is.False(Util.array2DEquals({{"a", "b", "c"}, {"1", "2", "3"}}, {{"a", "b", "c"}, {"1", "2"}}), false)
        assert.is.False(Util.array2DEquals({{"a", "b", "c"}, {"1", "2", "3"}}, {{"1", "2", "3"}, {"a", "b", "c"}}), false)
        assert.is.False(Util.array2DEquals({{"a", "b", "c"}, {"1", "2", "3"}}, {}), false)
    end)

    it("test arrayRemoveDuplications", function()
        assert.are.same({'data', 'data1', 'data2', 'data3'},Util.arrayRemoveDuplications({"data", "data1", "data2", "data1", "data2", "data3"}))
    end)

    it("test replaceInOfMatcher", function()
        assert.are.equals("r_sub == 'admin' && (r_obj == 'a' || r_obj == 'b')", Util.replaceInOfMatcher("r_sub == 'admin' && r_obj in ('a', 'b')"))
        assert.are.equals("(keyGet2(r_obj, p_obj, 'id') == 'age' || keyGet2(r_obj, p_obj, 'id') == 'name') && r_act == p_act", Util.replaceInOfMatcher("keyGet2(r_obj, p_obj, 'id') in ('age', 'name') && r_act == p_act"))
        assert.are.equals("(r_obj == 'a,b' || r_obj == 'c') && r_act == 'x in (y)'", Util.replaceInOfMatcher("r_obj in ('a,b', 'c') && r_act == 'x in (y)'"))
        assert.are.equals("(r_obj == 'a')", Util.replaceInOfMatcher("r_obj in ('a')"))
        assert.are.equals("(false)", Util.replaceInOfMatcher("r_obj in ()"))
    end)

    it("test trim", function()
        assert.are.equals("abc",Util.trim("abc"))
        assert.are.equals("abc",Util.trim(" abc "))
        assert.are.equals("abc",Util.trim("abc   "))
        assert.are.equals("abc",Util.trim("   abc"))
    end)

    it("test split", function()
        assert.are.same({"a", "b", "c"}, Util.split("a ,b ,c", ","))
        assert.are.same({"a", "b", "c"}, Util.split("a,b,c", ","))
        assert.are.same({"a", "b", "c"}, Util.split("a, b, c", ","))
        assert.are.same({"a", "b", "c"}, Util.split("  a,     b   ,c     ", ","))
    end)

    it("test isOnlyWhitespaces", function()
        assert.is.True(Util.isOnlyWhitespaces("     "))
        assert.is.True(Util.isOnlyWhitespaces(""))
        assert.is.True(Util.isOnlyWhitespaces("\t\t"))
        assert.is.False(Util.isOnlyWhitespaces("  abc"))
        assert.is.False(Util.isOnlyWhitespaces("abc\t"))
        assert.is.False(Util.isOnlyWhitespaces("\""))
    end)
    
    it("test splitEnhanced", function()
        assert.are.same({"a", "b", "c"}, Util.splitEnhanced("a ,b ,c", ",", true))
        assert.are.same({"a", "b", "c"}, Util.splitEnhanced("a,b,c", ",", true))
        assert.are.same({"a", "b", "c"}, Util.splitEnhanced("a, b, c", ",", true))
        assert.are.same({"a", "b", "c"}, Util.splitEnhanced("  a,     b   ,c     ", ",", true))

        assert.are.same({"a", " b", " c"}, Util.splitEnhanced('a, b, c', ",", false))
        assert.are.same({"a", "b", "c"}, Util.splitEnhanced('a,b,c', ",", false))
        assert.are.same({"    a", "b", "c"}, Util.splitEnhanced('    a,b,c', ",", false))
        assert.are.same({"a, b", "c"}, Util.splitEnhanced('"a, b", c', ",", true))
        assert.are.same({"a,   b", "c"}, Util.splitEnhanced('"   a,   b", c', ",", true))
        assert.are.same({"a == \"b\"", "c"}, Util.splitEnhanced('a == "b", c', ",", true))
        assert.are.same({"a == \"b\"", "c"}, Util.splitEnhanced('"a == ""b"" ", c', ",", true))
        assert.are.same({"a", "b, c"}, Util.splitEnhanced('a, "b, c"', ",", true))
        assert.are.same({"p", "a, b", "c, d", "e"}, Util.splitEnhanced('p, "a, b", "c, d", e', ",", true))
        assert.are.same({"p", 'say "hi"', "c, d"}, Util.splitEnhanced('p, "say ""hi""", "c, d"', ",", true))

        assert.has_error(function () Util.splitEnhanced('a, "b, c"   ', ",", true) end, "Quoted fields cannot have extra characters outside double quotes.")
        assert.has_error(function () Util.splitEnhanced('"a, b" hello, c', ",", true) end, "Quoted fields cannot have extra characters outside double quotes.")
        assert.has_error(function () Util.splitEnhanced('a, b, "c  ') end, "Unmatched quotes.")
    end)

    it("test isInstance", function()
        local parent = {}
        parent.__index = parent
        local child = {}
        setmetatable(child, parent)
        local notChild = {}
        assert.is.True(Util.isInstance(child, parent))
        assert.is.False(Util.isInstance(notChild, parent))
    end)
end)
