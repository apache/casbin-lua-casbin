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

describe("Multiple Enforcers tests", function ()
    it("multiple newEnforcerFromText test (issue: race condition)", function ()
        -- This test simulates the issue from GitHub where creating multiple 
        -- enforcers would cause race conditions with the global logging variable
        
        local model1 = [[
            [request_definition]
            r = path, method

            [policy_definition]
            p = path, method, eft

            [policy_effect]
            e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

            [matchers]
            m = regexMatch(r.path, p.path) && keyMatch(r.method, p.method)
        ]]

        local policy1 =[[
            p, ^/cate/sample/gen_label_no,              POST, allow
            p, ^/cate/sample/.*/[print|reprint],        PUT,  allow
        ]]

        local model2 = [[
            [request_definition]
            r = user, path, method

            [policy_definition]
            p = role, path, method

            [role_definition]
            g = _, _

            [policy_effect]
            e = some(where (p.eft == allow))

            [matchers]
            m = (g(r.user, p.role) || keyMatch(r.user, p.role)) && regexMatch(r.path, p.path) && keyMatch(r.method, p.method)
        ]]

        local policy2 =[[
            p, *,          ^/$,                         GET
            p, *,          ^/portal,                    GET
            p, *,          ^/admin,                     GET

            p, sys-admin,  *,                           *
            g, sys-admin,       guests
        ]]

        -- Create first enforcer
        local ex2 = Enforcer:newEnforcerFromText(model2, policy2)
        local pass2 = ex2:enforce("guests", "/", "GET")
        assert.is.True(pass2)

        -- Create second enforcer
        local ex1 = Enforcer:newEnforcerFromText(model1, policy1)
        local pass1 = ex1:enforce("/cate/sample/gen_label_no", "POST")
        assert.is.True(pass1)

        -- Test first enforcer again
        local pass3 = ex2:enforce("guests", "/", "GET")
        assert.is.True(pass3)
    end)
end)
