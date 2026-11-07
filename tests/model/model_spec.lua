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

local Model = require("src.model.Model")
local path = os.getenv("PWD") or io.popen("cd"):read()

local basic_path  = path .. "/examples/basic_model.conf"
local rbac_path = path .. "/examples/rbac_model.conf"
local rbac_with_domains_path = path .. "/examples/rbac_with_domains_model.conf"

describe("model tests", function()

    it("test getPolicy", function ()
        local m = Model:new()
        m:loadModel(basic_path)

        local rule = {'admin', 'domain1', 'data1', 'read'}
        m:addPolicy("p", "p", rule)

        assert.are.same({rule}, m:getPolicy("p", "p"))
    end)

    it("test hasPolicy", function ()
        local m = Model:new()
        m:loadModel(basic_path)

        local rule = {'admin', 'domain1', 'data1', 'read'}
        m:addPolicy("p", "p", rule)

        assert.is.True(m:hasPolicy("p", "p", rule))
    end)

    it("test hasPolicies", function ()
        local m = Model:new()
        m:loadModel(basic_path)
        local rule = {'admin', 'domain1', 'data1', 'read'}
        m:addPolicy("p", "p", rule)
        local rule1={'admin', 'domain2', 'data2', 'read'}
        m:addPolicy("p", "p", rule1)
        local rule2={'admin', 'domain3', 'data3', 'read'}
        m:addPolicy("p", "p", rule2)
        local rule3={'admin', 'domain4', 'data4', 'read'}
        local rulesallmatched={rule,rule1,rule2}
        local rulesonematched={rule,rule3}
        local rulesnotmatched={rule3}
        assert.is.True(m:hasPolicies("p", "p", rulesallmatched))
        assert.is.True(m:hasPolicies("p", "p", rulesonematched))
        assert.is.False(m:hasPolicies("p", "p", rulesnotmatched))
    end)

    it("test addPolicy", function ()
        local m = Model:new()
        m:loadModel(basic_path)

        local rule = {'admin', 'domain1', 'data1', 'read'}
        assert.is.False(m:hasPolicy("p", "p", rule))

        m:addPolicy("p", "p", rule)

        assert.is.True(m:hasPolicy("p", "p", rule))
    end)

    it("test addPoliciesWithAffected", function ()
        local m = Model:new()
        m:loadModel(basic_path)

        local rules = {{'admin', 'domain1', 'data1', 'read'},{'admin', 'domain2', 'data2', 'read'},{'admin', 'domain1', 'data1', 'write'}}
        assert.is.False(m:hasPolicies("p", "p", rules))

        assert.are.same(rules,m:addPoliciesWithAffected("p", "p", rules))
        assert.is.True(m:hasPolicies("p", "p", rules))

        local rules1 = {{'Alice', 'domain1', 'data1', 'read'},{'Bob', 'domain2', 'data2', 'read'},{'admin', 'domain1', 'data1', 'write'}}
        assert.is.True(m:hasPolicies("p", "p", rules1))

        assert.are.same({{'Alice', 'domain1', 'data1', 'read'},{'Bob', 'domain2', 'data2', 'read'}},m:addPoliciesWithAffected("p", "p", rules1))
        assert.is.True(m:hasPolicy("p", "p", {'Alice', 'domain1', 'data1', 'read'}))
        assert.is.True(m:hasPolicy("p", "p", {'Bob', 'domain2', 'data2', 'read'}))

    end)

    it("test removePolicy", function ()
        local m = Model:new()
        m:loadModel(basic_path)

        local rule = {'admin', 'domain1', 'data1', 'read'}
        assert.is.False(m:hasPolicy("p", "p", rule))

        m:addPolicy("p", "p", rule)
        assert.is.True(m:hasPolicy("p", "p", rule))

        m:removePolicy("p", "p", rule)
        assert.is.False(m:hasPolicy("p", "p", rule))
        assert.is.False(m:removePolicy("p", "p", rule))
    end)

    it("test removePoliciesWithEffected", function ()
        local m = Model:new()
        m:loadModel(basic_path)

        local rules = {{'admin', 'domain1', 'data1', 'read'},{'admin', 'domain2', 'data2', 'read'},{'admin', 'domain1', 'data1', 'write'}}
        assert.is.False(m:hasPolicies("p", "p", rules))

        m:addPolicies("p", "p", rules)
        assert.is.True(m:hasPolicies("p", "p", rules))

        assert.are.same(rules,m:removePoliciesWithEffected("p", "p", rules))
        assert.is.False(m:hasPolicies("p", "p", rules))
        assert.is.False(m:removePolicy("p", "p", rules[1]))

        m:addPolicies("p", "p", rules)
        assert.is.True(m:hasPolicies("p", "p", rules))

        local removeList={{'Alice', 'domain1', 'data1', 'read'},{'admin', 'domain2', 'data2', 'read'},{'admin', 'domain1', 'data1', 'write'}}
        assert.is.False(m:hasPolicy("p", "p", {'Alice', 'domain1', 'data1', 'read'}))

        assert.are.same({{'admin', 'domain2', 'data2', 'read'},{'admin', 'domain1', 'data1', 'write'}},m:removePoliciesWithEffected("p", "p", removeList))
        assert.is.False(m:hasPolicy("p", "p", removeList[2]))
        assert.is.False(m:removePolicy("p", "p", removeList[3]))
    end)

    it("test addRolePolicy", function ()
        local m = Model:new()
        m:loadModel(rbac_path)

        local p_rule1 = {'alice', 'data1', 'read'}
        m:addPolicy("p", "p", p_rule1)
        assert.is.True(m:hasPolicy("p", "p", p_rule1))

        local p_rule2 = {'data2_admin', 'data2', 'read'}
        m:addPolicy("p", "p", p_rule2)
        assert.is.True(m:hasPolicy("p", "p", p_rule2))

        local g_rule = {'alice', 'data2_admin'}
        m:addPolicy("g", "g", g_rule)
        assert.is.True(m:hasPolicy("g", "g", g_rule))

        assert.are.same({p_rule1, p_rule2}, m:getPolicy("p", "p"))
        assert.are.same({g_rule}, m:getPolicy("g", "g"))
    end)

    it("test updatePolicy", function ()
        local m = Model:new()
        m:loadModel(basic_path)

        local oldRule = {'admin', 'domain1', 'data1', 'read'}
        local newRule = {'admin', 'domain1', 'data2', 'read'}

        m:addPolicy("p", "p", oldRule)
        assert.is.True(m:hasPolicy("p", "p", oldRule))

        m:updatePolicy("p", "p", oldRule, newRule)
        assert.is.False(m:hasPolicy("p", "p", oldRule))
        assert.is.True(m:hasPolicy("p", "p", newRule))
    end)

    it("test updatePolicies", function ()
        local m = Model:new()
        m:loadModel(basic_path)

        local oldRules = {
            {'admin', 'domain1', 'data1', 'read'},
            {'admin', 'domain1', 'data2', 'read'},
            {'admin', 'domain1', 'data3', 'read'}
        }
        local newRules = {
            {'admin', 'domain1', 'data4', 'read'},
            {'admin', 'domain1', 'data5', 'read'},
            {'admin', 'domain1', 'data6', 'read'}
        }

        m:addPolicies("p", "p", oldRules)

        for _, oldRule in pairs(oldRules) do
            assert.is.True(m:hasPolicy("p", "p", oldRule))
        end

        m:updatePolicies("p", "p", oldRules, newRules)

        for _, oldRule in pairs(oldRules) do
            assert.is.False(m:hasPolicy("p", "p", oldRule))
        end

        for _, newRule in pairs(newRules) do
            assert.is.True(m:hasPolicy("p", "p", newRule))
        end

        local oldRules1 = {
            {'admin', 'domain1', 'data4', 'read'},
            {'admin', 'domain1', 'data5', 'read'},
        }
        local newRules1 = {
            {'admin', 'domain1', 'data1', 'read'},
            {'admin', 'domain1', 'data2', 'read'}
        }

        local resRules1 = {
            {'admin', 'domain1', 'data1', 'read'},
            {'admin', 'domain1', 'data2', 'read'},
            {'admin', 'domain1', 'data6', 'read'}
        }

        for _, oldRule in pairs(oldRules1) do
            assert.is.True(m:hasPolicy("p", "p", oldRule))
        end

        m:updatePolicies("p", "p", oldRules1, newRules1)

        for _, oldRule in pairs(oldRules1) do
            assert.is.False(m:hasPolicy("p", "p", oldRule))
        end

        for _, newRule in pairs(newRules1) do
            assert.is.True(m:hasPolicy("p", "p", newRule))
        end

        assert.is.same(resRules1,m:getPolicy("p", "p"))
    end)

    it("test clearPolicy", function ()
        local m = Model:new()
        m:loadModel(basic_path)

        local rule = {
            {'admin', 'domain1', 'data1', 'read'},
            {'admin', 'domain1', 'data2', 'read'}
        }
        m:addPolicies("p", "p", rule)
        assert.are.same(rule, m:getPolicy("p", "p"))

        m:clearPolicy()
        assert.are.same({}, m:getPolicy("p", "p"))
    end)

    it("test removeFilteredPolicy", function ()
        local m = Model:new()
        m:loadModel(rbac_with_domains_path)

        local rule = {'admin', 'domain1', 'data1', 'read'}
        m:addPolicy("p", "p", rule)

        local res = m:removeFilteredPolicy("p", "p", 1, {"domain1", "data1"})
        assert.is.True(res)

        res = m:removeFilteredPolicy("p", "p", 1, {"domain1", "data1"})
        assert.is.False(res)
    end)

    it("test updateFilteredPolicies", function ()
        local m = Model:new()
        m:loadModel(rbac_with_domains_path)

        local rules = {
            {'admin', 'domain1', 'data1', 'read'},
            {'admin1', 'domain1', 'data1', 'read'},
            {'admin', 'domain2', 'data3', 'read'}
        }
        m:addPolicies("p", "p", rules)

        local newRules = {
            {'admin', 'domain1', 'data1', 'write'},
            {'admin1', 'domain1', 'data1', 'write'},
        }

        m:updateFilteredPolicies("p", "p", 1, {"domain1", "data1"},newRules)
        local resRules = {
            {'admin', 'domain1', 'data1', 'write'},
            {'admin1', 'domain1', 'data1', 'write'},
            {'admin', 'domain2', 'data3', 'read'}
        }

        assert.are.same(resRules, m:getPolicy("p","p"))

    end)

    it("test getFilteredPolicy", function ()
        local m = Model:new()
        m:loadModel(rbac_with_domains_path)

        local rules = {
            {'admin', 'domain1', 'data1', 'read'},
            {'admin', 'domain1', 'data2', 'read'},
            {'admin', 'domain2', 'data3', 'read'}
        }
        m:addPolicies("p", "p", rules)

        local res = m:getFilteredPolicy("p", "p", 1, "domain1")
        local filteredRules = {
            {'admin', 'domain1', 'data1', 'read'},
            {'admin', 'domain1', 'data2', 'read'}
        }
        assert.are.same(filteredRules, res)

    end)

	it("test toText", function ()
        local m = Model:new()
        m:loadModel(basic_path)
        local res = m:toText()
        local saveText="[request_definition]\nr = sub, obj, act\n[policy_definition]\np = sub, obj, act\n[policy_effect]\ne = some(where (p.eft == allow))\n[matchers]\nm = r.sub == p.sub && r.obj == p.obj && r.act == p.act\n"
        assert.are.same(saveText, res)

    end)

    it("test printPolicy and printModel", function ()
        local m = Model:new()
        m:loadModel(basic_path)
        assert.has_no.errors(function ()
            m:printModel()
            m:printPolicy()
        end)
    end)

    it("test copy", function ()
        local m = Model:new()
        m:loadModel(basic_path)

        local rule = {'admin', 'domain1', 'data1', 'read'}
        m:addPolicy("p", "p", rule)

        assert.is.same(m.model,m:copy())
    end)

end)
