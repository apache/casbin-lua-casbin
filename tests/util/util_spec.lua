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
    end)

    it("test removeComments", function()
        assert.are.equals("r.act == p.act", Util.removeComments("r.act == p.act # comments"))
        assert.are.equals("r.act == p.act", Util.removeComments("r.act == p.act#comments"))
        assert.are.equals("r.act == p.act", Util.removeComments("r.act == p.act###"))
        assert.are.equals("", Util.removeComments("### comments"))
        assert.are.equals("r.act == p.act", Util.removeComments("r.act == p.act"))
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
