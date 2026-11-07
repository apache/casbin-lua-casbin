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

local Log = require("src.util.Log")

local path = os.getenv("PWD") or io.popen("cd"):read()

describe("log tests", function ()
    
    it("test console logger", function ()
        local logger = Log.getLogger()
        assert.has_no.errors(function ()
            logger:info("logging to console")
        end)
    end)

    it("test file logger", function ()
        local filePath = path .. "/testLogFile.log"
        local logger = Log:getFileLogger(filePath)
        logger:info("new log started")
        assert.has_no.errors(function ()
            local f = io.open(filePath, "r")
            if f == nil then error("file does not exist") end
        end)
    end)

    it("test filePath error", function ()
        assert.has_error(function ()
            local logger = Log:getFileLogger()
            logger:info("test log")
        end)
    end)
end)