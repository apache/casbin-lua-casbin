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

local Enforcer = require("src.main.Enforcer")
local BuiltInFunctions = require "src.util.BuiltInFunctions"
local path = os.getenv("PWD") or io.popen("cd"):read()

describe("Enforcer tests", function ()
    it("basic test", function ()
        local model  = path .. "/examples/basic_model.conf"
        local policy  = path .. "/examples/basic_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.False(e:enforce("alice", "data2", "read"))
        assert.is.False(e:enforce("bob", "data1", "write"))
        assert.is.True(e:enforce("bob", "data2", "write"))
    end)

    it("basic without spaces test", function ()
        local model  = path .. "/examples/basic_model_without_spaces.conf"
        local policy  = path .. "/examples/basic_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.False(e:enforce("alice", "data1", "write"))
        assert.is.False(e:enforce("alice", "data2", "read"))
        assert.is.False(e:enforce("alice", "data2", "write"))
        assert.is.False(e:enforce("bob", "data1", "read"))
        assert.is.False(e:enforce("bob", "data1", "write"))
        assert.is.False(e:enforce("bob", "data2", "read"))
        assert.is.True(e:enforce("bob", "data2", "write"))
    end)

    it("basic with root model test", function ()
        local model  = path .. "/examples/basic_with_root_model.conf"
        local policy  = path .. "/examples/basic_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("root", "any", "any"))
    end)

    it("basic without resources test", function ()
        local model  = path .. "/examples/basic_without_resources_model.conf"
        local policy  = path .. "/examples/basic_without_resources_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("alice", "read"))
        assert.is.False(e:enforce("alice", "write"))
        assert.is.True(e:enforce("bob", "write"))
        assert.is.False(e:enforce("bob", "read"))
    end)

    it("basic without users test", function ()
        local model  = path .. "/examples/basic_without_users_model.conf"
        local policy  = path .. "/examples/basic_without_users_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("data1", "read"))
        assert.is.False(e:enforce("data1", "write"))
        assert.is.True(e:enforce("data2", "write"))
        assert.is.False(e:enforce("data2", "read"))
    end)

    it("keyMatch test", function ()
        local model  = path .. "/examples/keymatch_model.conf"
        local policy  = path .. "/examples/keymatch_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("alice", "/alice_data/test", "GET"))
        assert.is.False(e:enforce("alice", "/bob_data/test", "GET"))
        assert.is.True(e:enforce("cathy", "/cathy_data", "GET"))
        assert.is.True(e:enforce("cathy", "/cathy_data", "POST"))
        assert.is.False(e:enforce("cathy", "/cathy_data/12", "POST"))
    end)

    it("keyMatch2 test", function ()
        local model  = path .. "/examples/keymatch2_model.conf"
        local policy  = path .. "/examples/keymatch2_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("alice", "/alice_data/resource", "GET"))
        assert.is.True(e:enforce("alice", "/alice_data2/123/using/456", "GET"))
    end)

    it("priority test", function ()
        local model  = path .. "/examples/priority_model.conf"
        local policy  = path .. "/examples/priority_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.False(e:enforce("alice", "data1", "write"))
        assert.is.False(e:enforce("alice", "data2", "read"))
        assert.is.False(e:enforce("alice", "data2", "write"))

        assert.is.False(e:enforce("bob", "data1", "read"))
        assert.is.False(e:enforce("bob", "data1", "write"))
        assert.is.True(e:enforce("bob", "data2", "read"))
        assert.is.False(e:enforce("bob", "data2", "write"))
    end)

    it("priority indeterminate test", function ()
        local model  = path .. "/examples/priority_model.conf"
        local policy  = path .. "/examples/priority_indeterminate_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.False(e:enforce("alice", "data1", "read"))
    end)

    it("rbac test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/rbac_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.True(e:enforce("alice", "data2", "read"))
        assert.is.True(e:enforce("alice", "data2", "write"))
        assert.is.False(e:enforce("bob", "data1", "read"))
        assert.is.True(e:enforce("bob", "data2", "write"))
        assert.is.False(e:enforce("bogus", "data2", "write")) -- Non-existent subject
    end)

    it("rbac empty policy test", function ()
        local model  = path .. "/examples/rbac_model.conf"
        local policy  = path .. "/examples/empty_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.False(e:enforce("alice", "data1", "read"))
        assert.is.False(e:enforce("bob", "data1", "read"))
        assert.is.False(e:enforce("bob", "data2", "write"))
        assert.is.False(e:enforce("alice", "data2", "read"))
        assert.is.False(e:enforce("alice", "data2", "write"))
    end)

    it("rbac with deny test", function ()
        local model  = path .. "/examples/rbac_with_deny_model.conf"
        local policy  = path .. "/examples/rbac_with_deny_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.True(e:enforce("bob", "data2", "write"))
        assert.is.True(e:enforce("alice", "data2", "read"))
        assert.is.False(e:enforce("alice", "data2", "write"))
    end)

    it("rbac with domains test", function ()
        local model  = path .. "/examples/rbac_with_domains_model.conf"
        local policy  = path .. "/examples/rbac_with_domains_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("alice", "domain1", "data1", "read"))
        assert.is.True(e:enforce("alice", "domain1", "data1", "write"))
        assert.is.False(e:enforce("alice", "domain1", "data2", "read"))
        assert.is.False(e:enforce("alice", "domain1", "data2", "write"))

        assert.is.False(e:enforce("bob", "domain2", "data1", "read"))
        assert.is.False(e:enforce("bob", "domain2", "data1", "write"))
        assert.is.True(e:enforce("bob", "domain2", "data2", "read"))
        assert.is.True(e:enforce("bob", "domain2", "data2", "write"))
    end)

    it("rbac with not deny test", function ()
        local model  = path .. "/examples/rbac_with_not_deny_model.conf"
        local policy  = path .. "/examples/rbac_with_deny_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.False(e:enforce("alice", "data2", "write"))
    end)

    it("rbac with resource roles test", function ()
        local model  = path .. "/examples/rbac_with_resource_roles_model.conf"
        local policy  = path .. "/examples/rbac_with_resource_roles_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.True(e:enforce("alice", "data1", "write"))
        assert.is.False(e:enforce("alice", "data2", "read"))
        assert.is.True(e:enforce("alice", "data2", "write"))

        assert.is.False(e:enforce("bob", "data1", "read"))
        assert.is.False(e:enforce("bob", "data1", "write"))
        assert.is.False(e:enforce("bob", "data2", "read"))
        assert.is.True(e:enforce("bob", "data2", "write"))
    end)

    it("rbac with pattern test", function ()
        local model  = path .. "/examples/rbac_with_pattern_model.conf"
        local policy  = path .. "/examples/rbac_with_pattern_policy.csv"

        local e = Enforcer:new(model, policy)

        -- set matching function to keyMatch2
        e.rmMap["g2"].matchingFunc = BuiltInFunctions.keyMatch2

        assert.is.True(e:enforce("alice", "/book/1", "GET"))
        assert.is.True(e:enforce("alice", "/book/2", "GET"))
        assert.is.True(e:enforce("alice", "/pen/1", "GET"))
        assert.is.False(e:enforce("alice", "/pen/2", "GET"))
        assert.is.False(e:enforce("bob", "/book/1", "GET"))
        assert.is.False(e:enforce("bob", "/book/2", "GET"))
        assert.is.True(e:enforce("bob", "/pen/1", "GET"))
        assert.is.True(e:enforce("bob", "/pen/2", "GET"))

        -- replace keyMatch2 with keyMatch3
        e.rmMap["g2"].matchingFunc = BuiltInFunctions.keyMatch3
        assert.is.True(e:enforce("alice", "/book2/1", "GET"))
        assert.is.True(e:enforce("alice", "/book2/2", "GET"))
        assert.is.True(e:enforce("alice", "/pen2/1", "GET"))
        assert.is.False(e:enforce("alice", "/pen2/2", "GET"))
        assert.is.False(e:enforce("bob", "/book2/1", "GET"))
        assert.is.False(e:enforce("bob", "/book2/2", "GET"))
        assert.is.True(e:enforce("bob", "/pen2/1", "GET"))
        assert.is.True(e:enforce("bob", "/pen2/2", "GET"))
    end)

    it("rbac domain pattern test", function ()
        local model  = path .. "/examples/rbac_with_domain_pattern_model.conf"
        local policy  = path .. "/examples/rbac_with_domain_pattern_policy.csv"

        local e = Enforcer:new(model, policy)
        e:AddNamedDomainMatchingFunc("g", BuiltInFunctions.keyMatch2)

        assert.is.True(e:enforce("alice", "domain1", "data1", "read"))
        assert.is.True(e:enforce("alice", "domain1", "data1", "write"))
        assert.is.False(e:enforce("alice", "domain1", "data2", "read"))
        assert.is.False(e:enforce("alice", "domain1", "data2", "write"))
        assert.is.True(e:enforce("alice", "domain2", "data2", "read"))
        assert.is.True(e:enforce("alice", "domain2", "data2", "write"))
        assert.is.False(e:enforce("bob", "domain2", "data1", "read"))
        assert.is.False(e:enforce("bob", "domain2", "data1", "write"))
        assert.is.True(e:enforce("bob", "domain2", "data2", "read"))
        assert.is.True(e:enforce("bob", "domain2", "data2", "write"))
    end)

    it("rbac all pattern test", function ()
        local model  = path .. "/examples/rbac_with_all_pattern_model.conf"
        local policy  = path .. "/examples/rbac_with_all_pattern_policy.csv"

        local e = Enforcer:new(model, policy)
        e:AddNamedMatchingFunc("g", BuiltInFunctions.keyMatch2)
        e:AddNamedDomainMatchingFunc("g", BuiltInFunctions.keyMatch2)

        assert.is.True(e:enforce("alice", "domain1", "/book/1", "read"))
        assert.is.False(e:enforce("alice", "domain1", "/book/1", "write"))
        assert.is.False(e:enforce("alice", "domain2", "/book/1", "read"))
        assert.is.True(e:enforce("alice", "domain2", "/book/1", "write"))
    end)

    it("matcher using in operator bracket test", function ()
        local model  = path .. "/examples/rbac_model_matcher_using_in_op_bracket.conf"
        local policy  = path .. "/examples/rbac_policy_matcher_using_in_op_bracket.csv"

        local e = Enforcer:new(model,policy)

        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.True(e:enforce("alice", "data2", "read"))
        assert.is.True(e:enforce("alice", "data3", "read"))
        assert.is.False(e:enforce("anyone", "data1", "read"))
        assert.is.True(e:enforce("anyone", "data2", "read"))
        assert.is.True(e:enforce("anyone", "data3", "read"))
    end)

    it("abac with empty policy test", function ()
        local model  = path .. "/examples/abac_model.conf"
        local policy  = path .. "/examples/empty_policy.csv"

        local e = Enforcer:new(model, policy)
        local sub  = "alice"
        local obj = {
            Owner = "alice",
            id = "data1"
        }
        assert.is.True(e:enforce(sub, obj, "write"))
    end)

    it("abac sub_rule test", function ()
        local model  = path .. "/examples/abac_rule_model.conf"
        local policy  = path .. "/examples/abac_rule_policy.csv"
        local sub1 = {
            Name = "Alice",
            Age = 16
        }
        local sub2 = {
            Name = "Bob",
            Age = 20
        }
        local sub3 = {
            Name = "Alice",
            Age = 65
        }
        local e = Enforcer:new(model, policy)
        assert.is.False(e:enforce(sub1, "/data1", "read"))
        assert.is.False(e:enforce(sub1, "/data2", "read"))
        assert.is.False(e:enforce(sub1, "/data1", "write"))
        assert.is.True(e:enforce(sub1, "/data2", "write"))

        assert.is.True(e:enforce(sub2, "/data1", "read"))
        assert.is.False(e:enforce(sub2, "/data2", "read"))
        assert.is.False(e:enforce(sub2, "/data1", "write"))
        assert.is.True(e:enforce(sub2, "/data2", "write"))

        assert.is.False(e:enforce(sub3, "/data1", "write"))
        assert.is.True(e:enforce(sub3, "/data1", "read"))
        assert.is.False(e:enforce(sub3, "/data2", "read"))
        assert.is.True(e:enforce(sub1, "/data2", "write"))
    end)

    it("abac with multiple sub_rules test", function ()
        local model  = path .. "/examples/abac_multiple_rules_model.conf"
        local policy  = path .. "/examples/abac_multiple_rules_policy.csv"
        local e = Enforcer:new(model, policy)

        local sub1 = {
            name = "alice",
            age = 16
        }
        local sub2 = {
            name = "alice",
            age = 20
        }
        local sub3 = {
            name = "bob",
            age = 65
        }
        local sub4 = {
            name = "bob",
            age = 35
        }

        assert.is.False(e:enforce(sub1, "/data1", "read"))
        assert.is.False(e:enforce(sub1, "/data2", "read"))
        assert.is.False(e:enforce(sub1, "/data1", "write"))
        assert.is.False(e:enforce(sub1, "/data2", "write"))

        assert.is.True(e:enforce(sub2, "/data1", "read"))
        assert.is.False(e:enforce(sub2, "/data2", "read"))
        assert.is.False(e:enforce(sub2, "/data1", "write"))
        assert.is.False(e:enforce(sub2, "/data2", "write"))

        assert.is.False(e:enforce(sub3, "/data1", "read"))
        assert.is.False(e:enforce(sub3, "/data2", "read"))
        assert.is.False(e:enforce(sub3, "/data1", "write"))
        assert.is.False(e:enforce(sub3, "/data2", "write"))

        assert.is.False(e:enforce(sub4, "/data1", "read"))
        assert.is.False(e:enforce(sub4, "/data2", "read"))
        assert.is.False(e:enforce(sub4, "/data1", "write"))
        assert.is.True(e:enforce(sub4, "/data2", "write"))
    end)

    it("in of matcher test", function ()
        local model  = path .. "/examples/in_matcher_model.conf"
        local policy  = path .. "/examples/in_matcher_policy.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.True(e:enforce("alice", "data1", "write"))
        assert.is.False(e:enforce("alice", "data2", "read"))
        assert.is.False(e:enforce("alice", "data2", "write"))

        assert.is.False(e:enforce("bob", "data1", "read"))
        assert.is.False(e:enforce("bob", "data1", "write"))
        assert.is.True(e:enforce("bob", "data2", "read"))
        assert.is.True(e:enforce("bob", "data2", "write"))
    end)

    it("explicit priority test", function ()
        local model  = path .. "/examples/priority_model_explicit.conf"
        local policy  = path .. "/examples/priority_policy_explicit.csv"

        local e = Enforcer:new(model, policy)
        assert.is.True(e:enforce("alice", "data1", "write"))
        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.False(e:enforce("bob", "data2", "read"))
        assert.is.True(e:enforce("bob", "data2", "write"))
        assert.is.False(e:enforce("data1_deny_group", "data1", "read"))
        assert.is.False(e:enforce("data1_deny_group", "data1", "write"))
        assert.is.True(e:enforce("data2_allow_group", "data2", "read"))
        assert.is.True(e:enforce("data2_allow_group", "data2", "write"))

        local rule = {"1", "bob", "data2", "write", "deny"}
        e.model:addPolicy("p", "p", rule)
        e.model:sortPoliciesByPriority()
        e.model:printPolicy()

        assert.is.True(e:enforce("alice", "data1", "write"))
        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.False(e:enforce("bob", "data2", "read"))
        assert.is.False(e:enforce("bob", "data2", "write"))
        assert.is.False(e:enforce("data1_deny_group", "data1", "read"))
        assert.is.False(e:enforce("data1_deny_group", "data1", "write"))
        assert.is.True(e:enforce("data2_allow_group", "data2", "read"))
        assert.is.True(e:enforce("data2_allow_group", "data2", "write"))
    end)

    it("explicit subject priority test", function ()
        local model  = path .. "/examples/subject_priority_model_with_domain.conf"
        local policy  = path .. "/examples/subject_priority_policy_with_domain.csv"
        local e = Enforcer:new(model, policy)
        assert.is.False(e:enforce("alice", "data1","domain1", "write"))
        assert.is.False(e:enforce("bob", "data2","domain2", "write"))
        e.model:printPolicy()
        e.model:sortPoliciesBySubjectHierarchy()
        e.model:printPolicy()
        assert.is.True(e:enforce("alice", "data1","domain1", "write"))
        assert.is.True(e:enforce("bob", "data2","domain2", "write"))
    end)


    it("Batch Enforce test", function ()
        local model  = path .. "/examples/basic_model.conf"
        local policy  = path .. "/examples/basic_policy.csv"

        local e = Enforcer:new(model, policy)

        local res = {true, false, false, true}
        local requests = {
            {"alice", "data1", "read"},
            {"alice", "data2", "read"},
            {"bob", "data1", "write"},
            {"bob", "data2", "write"}
        }

        assert.is.Same(res, e:BatchEnforce(requests))
    end)

    it("enforceEx test", function ()

        local function test(e, ...)
            local _, p = e:enforceEx(...)
            return p
        end

        local model  = path .. "/examples/basic_model.conf"
        local policy  = path .. "/examples/basic_policy.csv"

        local e = Enforcer:new(model, policy)

        assert.is.Same({"alice", "data1", "read"}, test(e, "alice", "data1", "read"))
        assert.is.Same({}, test(e, "alice", "data1", "write"))
        assert.is.Same({}, test(e, "alice", "data2", "read"))
        assert.is.Same({}, test(e, "alice", "data2", "write"))
        assert.is.Same({}, test(e, "bob", "data1", "read"))
        assert.is.Same({}, test(e, "bob", "data1", "write"))
        assert.is.Same({}, test(e, "bob", "data2", "read"))
        assert.is.Same({"bob", "data2", "write"}, test(e, "bob", "data2", "write"))

        model  = path .. "/examples/rbac_model.conf"
        policy  = path .. "/examples/rbac_policy.csv"

        e = Enforcer:new(model, policy)

        assert.is.Same({"alice", "data1", "read"}, test(e, "alice", "data1", "read"))
        assert.is.Same({}, test(e, "alice", "data1", "write"))
        assert.is.Same({"data2_admin", "data2", "read"}, test(e, "alice", "data2", "read"))
        assert.is.Same({"data2_admin", "data2", "write"}, test(e, "alice", "data2", "write"))
        assert.is.Same({}, test(e, "bob", "data1", "read"))
        assert.is.Same({}, test(e, "bob", "data1", "write"))
        assert.is.Same({}, test(e, "bob", "data2", "read"))
        assert.is.Same({"bob", "data2", "write"}, test(e, "bob", "data2", "write"))

        model  = path .. "/examples/priority_model.conf"
        policy  = path .. "/examples/priority_policy.csv"

        e = Enforcer:new(model, policy)

        assert.is.Same({"alice", "data1", "read", "allow"}, test(e, "alice", "data1", "read"))
        assert.is.Same({"data1_deny_group", "data1", "write", "deny"}, test(e, "alice", "data1", "write"))
        assert.is.Same({}, test(e, "alice", "data2", "read"))
        assert.is.Same({}, test(e, "alice", "data2", "write"))
        assert.is.Same({}, test(e, "bob", "data1", "write"))
        assert.is.Same({"data2_allow_group", "data2", "read", "allow"}, test(e, "bob", "data2", "read"))
        assert.is.Same({"bob", "data2", "write", "deny"}, test(e, "bob", "data2", "write"))
    end)

    it("newEnforcerFromText test", function ()
        local modelText = [[
            [request_definition]
            r = sub, obj, act
            [policy_definition]
            p = sub, obj, act
            [role_definition]
            g = _, _
            [policy_effect]
            e = some(where (p.eft == allow))
            [matchers]
            m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
        ]]

        local policyText = [[
            p, alice, data1, read
            p, bob, data2, write
            p, data2_admin, data2, read
            p, data2_admin, data2, write
            g, alice, data2_admin
        ]]

        local e = Enforcer:newEnforcerFromText(modelText, policyText)

        assert.is.True(e:enforce("alice", "data1", "read"))
        assert.is.True(e:enforce("alice", "data2", "read"))
        assert.is.True(e:enforce("alice", "data2", "write"))
        assert.is.False(e:enforce("bob", "data1", "read"))
        assert.is.True(e:enforce("bob", "data2", "write"))
        assert.is.False(e:enforce("bogus", "data2", "write")) -- Non-existent subject
    end)

    it("multiple newEnforcerFromText with distinct definitions", function ()
        local model1 = [[
            [request_definition]
            r = path, method

            [policy_definition]
            p = path, method

            [policy_effect]
            e = some(where (p.eft == allow))

            [matchers]
            m = r.path == p.path && r.method == p.method
        ]]

        local policy1 = [[
            p, /alpha, GET
        ]]

        local model2 = [[
            [request_definition]
            r = user, path, method

            [policy_definition]
            p = user, path, method

            [policy_effect]
            e = some(where (p.eft == allow))

            [matchers]
            m = r.user == p.user && r.path == p.path && r.method == p.method
        ]]

        local policy2 = [[
            p, alice, /alpha, GET
        ]]

        local e2 = Enforcer:newEnforcerFromText(model2, policy2)
        assert.is.True(e2:enforce("alice", "/alpha", "GET"))

        local e1 = Enforcer:newEnforcerFromText(model1, policy1)
        assert.is.True(e1:enforce("/alpha", "GET"))

        local ok, res = pcall(e2.enforce, e2, "alice", "/alpha", "GET")
        assert.is.True(ok)
        assert.is.True(res)
    end)

    
    it("regexMatch test", function ()

        local model  = path .. "/examples/basic_model_with_regex.conf"
        local policy  = path .. "/examples/basic_policy_with_regex.csv"
        local e = Enforcer:new(model, policy)

        assert.is.True(e:enforce("admin", "/", "PUT"))
        assert.is.True(e:enforce("admin", "/admin", "GET"))
        assert.is.True(e:enforce("admin", "/admin/anything", "POST"))
        assert.is.False(e:enforce("admin123", "/admin", "PUT"))

        assert.is.True(e:enforce("user", "/users/alice", "GET"))
        assert.is.True(e:enforce("user", "/users/alice", "PUT"))
        assert.is.True(e:enforce("user123", "/users/alice", "PUT"))
        assert.is.False(e:enforce("user", "/users/", "PUT"))
        assert.is.False(e:enforce("user", "/users/123", "PUT"))
        assert.is.False(e:enforce("user", "/users/alice123456789", "PUT"))
        assert.is.False(e:enforce("user", "/admin", "PUT"))

        assert.is.True(e:enforce("guest", "/guest/test", "GET"))
        assert.is.False(e:enforce("guest", "/guest/test", "PUT"))
    end)
end)
