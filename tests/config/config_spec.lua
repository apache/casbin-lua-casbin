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

local Config = require("src.config.Config")
local path = os.getenv("PWD") or io.popen("cd"):read()
path  = path .. "/tests/config/test.ini"
local config = Config:newConfig(path)

describe("config tests", function()

    it("test default::key", function()
        assert.are.equals("true", config:get("debug"))
        assert.are.equals("act.wiki", config:get("url"))
    end)

    it("test redis::key", function()
        assert.are.equals("push1,push2", config:get("redis::redis.key"))
        assert.are.equals("127.0.0.1", config:get("mysql::mysql.dev.host"))
        assert.are.equals("10.0.0.1", config:get("mysql::mysql.master.host"))
    end)

    it("test math::key", function()
        assert.are.equals("64", config:get("math::math.i64"))
        assert.are.equals("64.1", config:get("math::math.f64"))
    end)

    it("test other::key", function()
        assert.are.equals("ATC自动化测试^-^&($#……#", config:get("other::name"))
        assert.are.equals("test key",config:get("other::key1"))
    end)

    it("test set", function()
        config:set("other::key1", "new test key")
        assert.are.equals("new test key",config:get("other::key1"))
        config:set("other::key1", "test key")
    end)

    it("test multi line", function()
        assert.are.equals("r.sub==p.sub && r.obj==p.obj", config:get("multi1::name"))
        assert.are.equals("r.sub==p.sub && r.obj==p.obj", config:get("multi2::name"))
        assert.are.equals("r.sub==p.sub && r.obj==p.obj", config:get("multi3::name"))
        assert.are.equals("", config:get("multi4::name"))
        assert.are.equals("r.sub==p.sub && r.obj==p.obj", config:get("multi5::name"))
    end)

    it("test get{type}", function()
        assert.are.equals("r.sub==p.sub && r.obj==p.obj", config:getString("multi5::name"))
        assert.are.same({"r.sub==p.sub && r.obj==p.obj"}, config:getStrings("multi5::name"))
        assert.has_error(function () config:getBool("multi5::name") end, "Not a boolean value")
        assert.has_error(function () config:getNum("multi5::name") end, "Not a num value")
    end)

end) 
