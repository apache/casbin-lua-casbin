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

local Config = require("src/config/Config")
local Policy = require("src/model/Policy")
local Assertion = require("src/model/Assertion")
local Util = require("src/util/Util")

local Model = Policy:new()

function Model:new()
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.model = {}
    o.sectionNameMap = {
        ["r"] = "request_definition",
        ["p"] = "policy_definition",
        ["g"] = "role_definition",
        ["e"] = "policy_effect",
        ["m"] = "matchers"
    }

    o.requiredSections = {"r", "p", "e", "m"} -- Minimal required sections for a model to be valid
    o.modCount = 0   -- used by CoreEnforcer to detect changes to Model

    -- PolicyOperations: [key] = POLICY_ADD/POLICY_REMOVE and value = string(key)
    o.PolicyOperations = {
        POLICY_ADD = "POLICY_ADD",
        POLICY_REMOVE = "POLICY_REMOVE"
    }
    return o
end

function Model:getModCount()
    return self.modCount
end

function Model:loadAssertion(model, cfg, sec, key)
    local value = cfg:getString(self.sectionNameMap[sec].."::"..key)
    return model:addDef(sec, key, value)
end

--[[
    * addDef adds an assertion to the model.
    *
    * @param sec the section, "p" or "g".
    * @param key the policy type, "p", "p2", .. or "g", "g2", ..
    * @param value the policy rule, separated by ", ".
    * @return succeeds or not.
]]
function Model:addDef(sec, key, value)

    if value == "" then return false end

    if self.model[sec] == nil then
        self.model[sec] = {}
    end

    if self.model[sec][key] == nil then
        self.model[sec][key] = {}
    end

    self.model[sec][key] = Assertion:new()
    self.model[sec][key].key = key
    self.model[sec][key].value = value
    self.model[sec][key].policyMap={}
    self.model[sec][key]:initPriorityIndex()
    if sec == "r" or sec == "p" then
        self.model[sec][key].tokens = Util.splitCommaDelimited(self.model[sec][key].value)
        for k, v in pairs(self.model[sec][key].tokens) do
            self.model[sec][key].tokens[k] = key .. "_" .. self.model[sec][key].tokens[k]
        end
    else
        self.model[sec][key].value = Util.removeComments(Util.escapeAssertion(self.model[sec][key].value))
    end

    if sec == "m" and string.find(self.model[sec][key].value,"in")~=nil then
        self.model[sec][key].value = string.gsub(string.gsub(self.model[sec][key].value,"%[","("),"%]",")")
    end

    self.modCount = self.modCount + 1
    return true
end

function Model:getKeySuffix(i)
     if i == 1 then
        return ""
    end

    return ""..i
end

function Model:loadSection(model, cfg, sec)
    local i = 1
    while true do
        if not self:loadAssertion(model, cfg, sec, sec..self:getKeySuffix(i)) then
            break;
        else
            i = i + 1
        end
    end
end

--[[
    * loadModel loads the model from model CONF file.
    *
    * @param path the path of the model file.
]]
function Model:loadModel(path)
    local cfg = Config:newConfig(path)

    self:loadSection(self, cfg, "r")
    self:loadSection(self, cfg, "p")
    self:loadSection(self, cfg, "e")
    self:loadSection(self, cfg, "m")

    self:loadSection(self, cfg, "g")
end

--[[
    * loadModelFromText loads the model from the text.
    *
    * @param text the model text.
]]
function Model:loadModelFromText(text)
    local cfg = Config:newConfigFromText(text)

    self:loadSection(self, cfg, "r")
    self:loadSection(self, cfg, "p")
    self:loadSection(self, cfg, "e")
    self:loadSection(self, cfg, "m")

    self:loadSection(self, cfg, "g")
end

--[[
    * saveSectionToText saves the section to the text.
    *
    * @return the section text.
]]
function Model:saveSectionToText(sec)
    local res = "[" .. self.sectionNameMap[sec] .. "]\n"

    if not self.model[sec] then
        return ""
    end

    for key, ast in pairs(self.model[sec]) do
        local val = ast.value:gsub("%_", ".")
        local x = string.format("%s = %s\n", key, val)

        res = res .. x
    end

    return res
end

--[[
    * toText saves the model to the text.
    *
    * @return the model text.
]]
function Model:toText()
    local tokenPatterns={}
    for _,ptype in pairs({"r","p"}) do
        for _,token in pairs(self.model[ptype][ptype].tokens) do
            tokenPatterns[token]=string.gsub (string.gsub (token,"^p_","p."),"^r_","r.")
        end
    end
    tokenPatterns["p_eft"] = "p.eft"

    local s=""
    local writeString=function(sec)
        local result=""
         for ptype,_ in pairs(self.model[sec]) do
            local value=self.model[sec][ptype].value
            for tokenPattern,newToken in pairs(tokenPatterns) do
                value=string.gsub(value,tokenPattern,newToken)
            end
            result=result..sec.." = "..value.."\n"
        end
        return result
    end
    s=s.."[request_definition]\n"..writeString("r").."[policy_definition]\n"..writeString("p")
    if self.model["g"] then
        s=s.."[role_definition]\n"
        for ptype,_ in pairs(self.model["g"]) do
            s=s..ptype.." = "..self.model["g"][ptype].value.."\n"
        end
    end
    s=s.."[policy_effect]\n"..writeString("e").."[matchers]\n"..writeString("m")
    return s
end

--  * printModel prints the model to the log.
function Model:printModel()
    self.logger:info("Model: \n")
    for k,v in pairs(self.model) do
        for k2, v2 in pairs(v) do
            self.logger:info("[%s.%s]:", k, k2)
            self.logger:info(v2)
        end
    end
end

local function getSubjectHierarchyMap(policies)
    local subjectHierarchyMap = { }
    --Tree structure of role
    local policyMap = { }
    for _, policy in pairs(policies) do
        if #policy < 2 then
            return nil, error("policy g expect 2 more params")
        end
        local domain=""
        if #policy~=2 then
            domain  = policy[3]
        end
        local child = domain.."::"..policy[1]
        local parent = domain.."::"..policy[2]
        if policyMap[parent]==nil then
            policyMap[parent]={}
        end
        table.insert(policyMap[parent], child)
        if subjectHierarchyMap[child]==nil then
            subjectHierarchyMap[child] = 0
        end
        if subjectHierarchyMap[parent]==nil then
            subjectHierarchyMap[parent] = 0
        end
        subjectHierarchyMap[child] = 1
    end
    local queue = {  }
    for k, v in pairs(subjectHierarchyMap) do
        if v == 0 then
            local root = k
            local lv = 0
            table.insert(queue,root)
            while #queue~=0 do
                local sz=#queue
                for i=1,sz do
                    local node=queue[1]
                    table.remove(queue,1)
                    subjectHierarchyMap[node] = lv
                    if policyMap[node]~=nil then
                        for _,child in pairs(policyMap[node]) do
                            table.insert(queue,child)
                        end
                    end
                end
                lv=lv+1
            end
        end
    end

    return subjectHierarchyMap, nil
end

function Model:sortPoliciesBySubjectHierarchy()
    if self.model["e"]["e"].value ~= "subjectPriority(p_eft) || deny" then
        return nil
    end
    local subIndex = 1
    local domainIndex = -1
    for ptype, assertion in pairs(self.model["p"]) do
        for index, token in pairs(assertion.tokens)  do
            if token == ptype.."_dom" then
            domainIndex = index
            break
            end
        end
        local subjectHierarchyMap, err = getSubjectHierarchyMap(self.model["g"]["g"].policy)
        if err ~= nil then
            return err
        end
        table.sort(assertion.policy, function(i, j)
            local domain1, domain2 = "", ""
            if domainIndex ~= -1 then
                domain1 = i[domainIndex]
                domain2 = j[domainIndex]
            end
            local name1, name2 =domain1.."::"..i[subIndex], domain2.."::".. j[subIndex]
            local p1 = subjectHierarchyMap[name1]
            local p2 = subjectHierarchyMap[name2]
            return p1 > p2
        end)
        for i, policy in pairs(assertion.policy) do
            assertion.policyMap[table.concat(policy, ",")] = i
        end
    end
    return nil
end

-- sortPoliciesByPriority sorts policies by their priorities if 'priority' token exists
function Model:sortPoliciesByPriority()
    if not self.model["p"] then return end

    for ptype, ast in pairs(self.model["p"]) do
        for inx, token in pairs(ast.tokens) do
            if token == ptype .. "_priority" then
                ast.priorityIndex = inx
                break
            end
        end
        if ast.priorityIndex == -1 then
            return
        end
        table.sort(ast.policy, function (a, b)
        return a[ast.priorityIndex] < b[ast.priorityIndex]
        end)
        for i,policy in pairs(ast.policy) do
            ast.policyMap[table.concat(policy,",")]=i
        end
     end
end

function Model:copy()
    return Util.deepCopy(self.model)
end

return Model
