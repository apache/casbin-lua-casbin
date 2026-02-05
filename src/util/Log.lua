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

-- The logging module for logging to console or any file
local Log = {
    enabled = true
}
Log.__index = Log

-- returns logger function for logging to console
function Log.getLogger()
    -- Lazy load to avoid global variable issues in OpenResty
    local Logging = require "logging"
    local o = {}
    setmetatable(o, Log)
    o.logger = Logging.new(function(self, level, message)
        print(level, message)
        return true
      end)
    return o
end

-- returns logger function for logging to file and @param: filePath = path of the log file
function Log:getFileLogger(filePath)
    if not filePath then
        error("no filePath for logger provided")
    end
    -- Lazy load to avoid global variable issues in OpenResty
    local fileLogging = require "logging.file"
    local o = {}
    self.__index = self
    setmetatable(o, self)
    o.logger = fileLogging(filePath)
    return o
end 

-- logs the information passed to it if log is enabled and logger exists
function Log:info(...)
    if self.enabled and self.logger then
        self.logger:info(...)
    end
end

return Log