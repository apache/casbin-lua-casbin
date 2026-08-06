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

local BuiltInFunctions = require("src.util.BuiltInFunctions")

describe("BuiltInFunctions tests", function ()
    it("keyMatch tests", function ()
        assert.has_error(function () BuiltInFunctions.keyMatchFunc({"/"}) end, "Expected 2 arguments, but got 1")
        assert.has_error(function () BuiltInFunctions.keyMatchFunc({"/foo/create/123", "/*", "/foo/update/123"}) end, "Expected 2 arguments, but got 3")
        assert.has_error(function () BuiltInFunctions.keyMatchFunc({"/foo", true}) end, "Argument must be a string")

        assert.is.False(BuiltInFunctions.keyMatch("/foo", "/"))
        assert.is.True(BuiltInFunctions.keyMatch("/foo", "/foo"))
        assert.is.True(BuiltInFunctions.keyMatch("/foo", "/foo*"))
        assert.is.False(BuiltInFunctions.keyMatch("/foo", "/foo/*"))
        assert.is.False(BuiltInFunctions.keyMatch("/foo/bar", "/foo"))
        assert.is.True(BuiltInFunctions.keyMatch("/foo/bar", "/foo*"))
        assert.is.True(BuiltInFunctions.keyMatch("/foo/bar", "/foo/*"))
        assert.is.False(BuiltInFunctions.keyMatch("/foobar", "/foo"))
        assert.is.True(BuiltInFunctions.keyMatch("/foobar", "/foo*"))
        assert.is.False(BuiltInFunctions.keyMatch("/foobar", "/foo/*"))
    end)

    it("keyGet tests", function ()
        assert.has_error(function () BuiltInFunctions.keyGetFunc({"/foo/bar/foo"}) end, "Expected 2 arguments, but got 1")
        assert.has_error(function () BuiltInFunctions.keyGetFunc({"/foo/bar/foo", "/foo/*", "/bar"}) end, "Expected 2 arguments, but got 3")
        assert.has_error(function () BuiltInFunctions.keyGetFunc({"/foo/bar/foo", true}) end, "Argument must be a string")

        assert.are.same("", BuiltInFunctions.keyGet("/foo", "/foo"))
        assert.are.same("", BuiltInFunctions.keyGet("/foo", "/foo*"))
        assert.are.same("", BuiltInFunctions.keyGet("/foo", "/foo/*"))
        assert.are.same("", BuiltInFunctions.keyGet("/foo/bar", "/foo"))
        assert.are.same("/bar", BuiltInFunctions.keyGet("/foo/bar", "/foo*"))
        assert.are.same("bar", BuiltInFunctions.keyGet("/foo/bar", "/foo/*"))
        assert.are.same("", BuiltInFunctions.keyGet("/foobar", "/foo"))
        assert.are.same("bar", BuiltInFunctions.keyGet("/foobar", "/foo*"))
        assert.are.same("", BuiltInFunctions.keyGet("/foobar", "/foo/*"))
    end)

    it("keyMatch2 tests", function ()
        assert.has_error(function () BuiltInFunctions.keyMatch2Func({"/"}) end, "Expected 2 arguments, but got 1")
        assert.has_error(function () BuiltInFunctions.keyMatch2Func({"/foo/create/123", "/*", "/foo/update/123"}) end, "Expected 2 arguments, but got 3")
        assert.has_error(function () BuiltInFunctions.keyMatch2Func({"/foo", true}) end, "Argument must be a string")

        assert.is.False(BuiltInFunctions.keyMatch2("/foo", "/"))
        assert.is.True(BuiltInFunctions.keyMatch2("/foo", "/foo"))
        assert.is.True(BuiltInFunctions.keyMatch2("/foo", "/foo*"))
        assert.is.False(BuiltInFunctions.keyMatch2("/foo", "/foo/*"))
        assert.is.False(BuiltInFunctions.keyMatch2("/foo/bar", "/foo"))  -- different with KeyMatch.
        assert.is.False(BuiltInFunctions.keyMatch2("/foo/bar", "/foo*"))
        assert.is.True(BuiltInFunctions.keyMatch2("/foo/bar", "/foo/*"))
        assert.is.False(BuiltInFunctions.keyMatch2("/foobar", "/foo"))  -- different with KeyMatch.
        assert.is.False(BuiltInFunctions.keyMatch2("/foobar", "/foo*"))
        assert.is.False(BuiltInFunctions.keyMatch2("/foobar", "/foo/*"))

        assert.is.False(BuiltInFunctions.keyMatch2("/", "/:resource"))
        assert.is.True(BuiltInFunctions.keyMatch2("/resource1", "/:resource"))
        assert.is.False(BuiltInFunctions.keyMatch2("/myid", "/:id/using/:resId"))
        assert.is.True(BuiltInFunctions.keyMatch2("/myid/using/myresid", "/:id/using/:resId"))

        assert.is.False(BuiltInFunctions.keyMatch2("/proxy/myid", "/proxy/:id/*"))
        assert.is.True(BuiltInFunctions.keyMatch2("/proxy/myid/", "/proxy/:id/*"))
        assert.is.True(BuiltInFunctions.keyMatch2("/proxy/myid/res", "/proxy/:id/*"))
        assert.is.True(BuiltInFunctions.keyMatch2("/proxy/myid/res/res2", "/proxy/:id/*"))
        assert.is.True(BuiltInFunctions.keyMatch2("/proxy/myid/res/res2/res3", "/proxy/:id/*"))
        assert.is.False(BuiltInFunctions.keyMatch2("/proxy/", "/proxy/:id/*"))

        assert.is.True(BuiltInFunctions.keyMatch2("/alice", "/:id"))
        assert.is.True(BuiltInFunctions.keyMatch2("/alice/all", "/:id/all"))
        assert.is.False(BuiltInFunctions.keyMatch2("/alice", "/:id/all"))
        assert.is.False(BuiltInFunctions.keyMatch2("/alice/all", "/:id"))

        assert.is.False(BuiltInFunctions.keyMatch2("/alice/all", "/:/all"))
    end)

    it("keyGet2 tests", function ()
        assert.has_error(function () BuiltInFunctions.keyGet2Func({"/foo"}) end, "Expected 3 arguments, but got 1")
        assert.has_error(function () BuiltInFunctions.keyGet2Func({"/foo", "/:bar"}) end, "Expected 3 arguments, but got 2")
        assert.has_error(function () BuiltInFunctions.keyGet2Func({"/foo", "/:bar", "bar", "foobar"}) end, "Expected 3 arguments, but got 4")
        assert.has_error(function () BuiltInFunctions.keyGet2Func({"/foo", "/:bar", true}) end, "Argument must be a string")

        assert.are.equal("",BuiltInFunctions.keyGet2("/foo", "/foo", "id"))
        assert.are.equal("",BuiltInFunctions.keyGet2("/foo", "/foo*", "id"))
        assert.are.equal("",BuiltInFunctions.keyGet2("/foo", "/foo/*", "id"))
        assert.are.equal("",BuiltInFunctions.keyGet2("/foo/bar", "/foo", "id"))
        assert.are.equal("",BuiltInFunctions.keyGet2("/foo/bar", "/foo*", "id"))
        assert.are.equal("",BuiltInFunctions.keyGet2("/foo/bar", "/foo/*", "id"))
        assert.are.equal("",BuiltInFunctions.keyGet2("/foobar", "/foo", "id"))
        assert.are.equal("",BuiltInFunctions.keyGet2("/foobar", "/foo*", "id"))
        assert.are.equal("",BuiltInFunctions.keyGet2("/foobar", "/foo/*", "id"))

        assert.are.equal("",BuiltInFunctions.keyGet2("/", "/:resource", "resource"))
        assert.are.equal("resource1",BuiltInFunctions.keyGet2("/resource1", "/:resource", "resource"))
        assert.are.equal("",BuiltInFunctions.keyGet2("/myid", "/:id/using/:resId", "id"))
        assert.are.equal("myid",BuiltInFunctions.keyGet2("/myid/using/myresid", "/:id/using/:resId", "id"))
        assert.are.equal("myresid",BuiltInFunctions.keyGet2("/myid/using/myresid", "/:id/using/:resId", "resId"))

        assert.are.equal("",BuiltInFunctions.keyGet2("/proxy/myid", "/proxy/:id/*", "id"))
        assert.are.equal("myid",BuiltInFunctions.keyGet2("/proxy/myid/", "/proxy/:id/*", "id"))
        assert.are.equal("myid",BuiltInFunctions.keyGet2("/proxy/myid/res", "/proxy/:id/*", "id"))
        assert.are.equal("myid",BuiltInFunctions.keyGet2("/proxy/myid/res/res2", "/proxy/:id/*", "id"))
        assert.are.equal("myid",BuiltInFunctions.keyGet2("/proxy/myid/res/res2/res3", "/proxy/:id/*", "id"))
        assert.are.equal("myid",BuiltInFunctions.keyGet2("/proxy/myid/res/res2/res3", "/proxy/:id/res/*", "id"))
        assert.are.equal("",BuiltInFunctions.keyGet2("/proxy/", "/proxy/:id/*", "id"))

        assert.are.equal("alice",BuiltInFunctions.keyGet2("/alice", "/:id", "id"))
        assert.are.equal("alice",BuiltInFunctions.keyGet2("/alice/all", "/:id/all", "id"))
        assert.are.equal("",BuiltInFunctions.keyGet2("/alice", "/:id/all", "id"))
        assert.are.equal("",BuiltInFunctions.keyGet2("/alice/all", "/:id", "id"))

        assert.are.equal("",BuiltInFunctions.keyGet2("/alice/all", "/:/all", ""))
    end)

    it("keyMatch3 tests", function ()
        assert.has_error(function () BuiltInFunctions.keyMatch3Func({"/"}) end, "Expected 2 arguments, but got 1")
        assert.has_error(function () BuiltInFunctions.keyMatch3Func({"/foo/create/123", "/*", "/foo/update/123"}) end, "Expected 2 arguments, but got 3")
        assert.has_error(function () BuiltInFunctions.keyMatch3Func({"/foo", true}) end, "Argument must be a string")

        assert.is.True(BuiltInFunctions.keyMatch3("/foo", "/foo"))
        assert.is.True(BuiltInFunctions.keyMatch3("/foo", "/foo*"))
        assert.is.False(BuiltInFunctions.keyMatch3("/foo", "/foo/*"))
        assert.is.False(BuiltInFunctions.keyMatch3("/foo/bar", "/foo"))
        assert.is.False(BuiltInFunctions.keyMatch3("/foo/bar", "/foo*"))
        assert.is.True(BuiltInFunctions.keyMatch3("/foo/bar", "/foo/*"))
        assert.is.False(BuiltInFunctions.keyMatch3("/foobar", "/foo"))
        assert.is.False(BuiltInFunctions.keyMatch3("/foobar", "/foo*"))
        assert.is.False(BuiltInFunctions.keyMatch3("/foobar", "/foo/*"))

        assert.is.False(BuiltInFunctions.keyMatch3("/", "/{resource}"))
        assert.is.True(BuiltInFunctions.keyMatch3("/resource1", "/{resource}"))
        assert.is.False(BuiltInFunctions.keyMatch3("/myid", "/{id}/using/{resId}"))
        assert.is.True(BuiltInFunctions.keyMatch3("/myid/using/myresid", "/{id}/using/{resId}"))

        assert.is.False(BuiltInFunctions.keyMatch3("/proxy/myid", "/proxy/{id}/*"))
        assert.is.True(BuiltInFunctions.keyMatch3("/proxy/myid/", "/proxy/{id}/*"))
        assert.is.True(BuiltInFunctions.keyMatch3("/proxy/myid/res", "/proxy/{id}/*"))
        assert.is.True(BuiltInFunctions.keyMatch3("/proxy/myid/res/res2", "/proxy/{id}/*"))
        assert.is.True(BuiltInFunctions.keyMatch3("/proxy/myid/res/res2/res3", "/proxy/{id}/*"))
        assert.is.False(BuiltInFunctions.keyMatch3("/proxy/", "/proxy/{id}/*"))

        assert.is.False(BuiltInFunctions.keyMatch3("/myid/using/myresid", "/{id/using/{resId}"))
    end)

    it("keyMatch4 tests", function ()
        assert.has_error(function () BuiltInFunctions.keyMatch4Func({"/parent/123/child/123"}) end, "Expected 2 arguments, but got 1")
        assert.has_error(function () BuiltInFunctions.keyMatch4Func({"/parent/123/child/123", "/parent/{id}/child/{id}", true}) end, "Expected 2 arguments, but got 3")
        assert.has_error(function () BuiltInFunctions.keyMatch4Func({"/parent/123/child/123", true}) end, "Argument must be a string")

        assert.is.True(BuiltInFunctions.keyMatch4("/parent/123/child/123", "/parent/{id}/child/{id}"))
        assert.is.False(BuiltInFunctions.keyMatch4("/parent/123/child/456", "/parent/{id}/child/{id}"))

        assert.is.True(BuiltInFunctions.keyMatch4("/parent/123/child/123", "/parent/{id}/child/{another_id}"))
        assert.is.True(BuiltInFunctions.keyMatch4("/parent/123/child/456", "/parent/{id}/child/{another_id}"))

        assert.is.True(BuiltInFunctions.keyMatch4("/parent/123/child/123/book/123", "/parent/{id}/child/{id}/book/{id}"))
        assert.is.False(BuiltInFunctions.keyMatch4("/parent/123/child/123/book/456", "/parent/{id}/child/{id}/book/{id}"))
        assert.is.False(BuiltInFunctions.keyMatch4("/parent/123/child/456/book/123", "/parent/{id}/child/{id}/book/{id}"))
        assert.is.False(BuiltInFunctions.keyMatch4("/parent/123/child/456/book/", "/parent/{id}/child/{id}/book/{id}"))
        assert.is.False(BuiltInFunctions.keyMatch4("/parent/123/child/456", "/parent/{id}/child/{id}/book/{id}"))

        assert.is.False(BuiltInFunctions.keyMatch4("/parent/123/child/123", "/parent/{i/d}/child/{i/d}"))

        -- Patterns without any {token} must still work instead of raising
        -- "number of tokens is not equal to number of values".
        assert.is.True(BuiltInFunctions.keyMatch4("data1", "data1"))
        assert.is.False(BuiltInFunctions.keyMatch4("data1", "data2"))
        assert.is.True(BuiltInFunctions.keyMatch4("/foo/bar", "/foo/*"))
        assert.is.False(BuiltInFunctions.keyMatch4("/bar/foo", "/foo/*"))

        -- The pattern is anchored, so it must match the whole key.
        assert.is.False(BuiltInFunctions.keyMatch4("/parent/123/child/123/extra", "/parent/{id}/child/{id}"))
        assert.is.False(BuiltInFunctions.keyMatch4("data11", "data1"))
    end)

    it("regexMatch tests", function ()
        assert.has_error(function () BuiltInFunctions.regexMatchFunc({"/topic/create"}) end, "Expected 2 arguments, but got 1")
        assert.has_error(function () BuiltInFunctions.regexMatchFunc({"/topic/create/123", "/topic/create", "/topic/update"}) end, "Expected 2 arguments, but got 3")
        assert.has_error(function () BuiltInFunctions.regexMatchFunc({"/topic/create", false}) end, "Argument must be a string")

        assert.is.True(BuiltInFunctions.regexMatch("/topic/create", "/topic/create"))
        assert.is.True(BuiltInFunctions.regexMatch("/topic/create/123", "/topic/create"))
        assert.is.False(BuiltInFunctions.regexMatch("/topic/delete", "/topic/create"))
        assert.is.False(BuiltInFunctions.regexMatch("/topic/edit", "/topic/edit/[0-9]+"))
        assert.is.True(BuiltInFunctions.regexMatch("/topic/edit/123", "/topic/edit/[0-9]+"))
        assert.is.False(BuiltInFunctions.regexMatch("/topic/edit/abc", "/topic/edit/[0-9]+"))
        assert.is.False(BuiltInFunctions.regexMatch("/foo/delete/123", "/topic/delete/[0-9]+"))
        assert.is.True(BuiltInFunctions.regexMatch("/topic/delete/0", "/topic/delete/[0-9]+"))
        assert.is.False(BuiltInFunctions.regexMatch("/topic/edit/123s", "/topic/delete/[0-9]+"))
    end)

    it("globMatch tests", function ()
        assert.has_error(function () BuiltInFunctions.globMatchFunc({"/foo"}) end, "Expected 2 arguments, but got 1")
        assert.has_error(function () BuiltInFunctions.globMatchFunc({"/foo", "/bar", "/foobar"}) end, "Expected 2 arguments, but got 3")
        assert.has_error(function () BuiltInFunctions.globMatchFunc({"/foo", 128}) end, "Argument must be a string")

        assert.is.True(BuiltInFunctions.globMatch("/foo", "/foo"))
        assert.is.True(BuiltInFunctions.globMatch("/foo", "/foo*"))
        assert.is.False(BuiltInFunctions.globMatch("/foo", "/foo/*"))
        assert.is.False(BuiltInFunctions.globMatch("/foo/bar", "/foo"))
        assert.is.False(BuiltInFunctions.globMatch("/foo/bar", "/foo*"))
        assert.is.True(BuiltInFunctions.globMatch("/foo/bar", "/foo/*"))
        assert.is.False(BuiltInFunctions.globMatch("/foobar", "/foo"))
        assert.is.True(BuiltInFunctions.globMatch("/foobar", "/foo*"))
        assert.is.False(BuiltInFunctions.globMatch("/foobar", "/foo/*"))

        assert.is.False(BuiltInFunctions.globMatch("/prefix/foo", "*/foo"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/foo", "*/foo*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/foo", "*/foo/*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/foo/bar", "*/foo"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/foo/bar", "*/foo*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/foo/bar", "*/foo/*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/foobar", "*/foo"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/foobar", "*/foo*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/foobar", "*/foo/*"))

        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foo", "*/foo"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foo", "*/foo*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foo", "*/foo/*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foo/bar", "*/foo"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foo/bar", "*/foo*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foo/bar", "*/foo/*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foobar", "*/foo"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foobar", "*/foo*"))
        assert.is.False(BuiltInFunctions.globMatch("/prefix/subprefix/foobar", "*/foo/*"))

    end)

    it("IPMatch tests", function ()
        assert.has_error(function () BuiltInFunctions.IPMatchFunc({"192.168.2.123"}) end, "Expected 2 arguments, but got 1")
        assert.has_error(function () BuiltInFunctions.IPMatchFunc({"192.168.2.123", "192.168.2.0/24", "192.168.2.0/26"}) end, "Expected 2 arguments, but got 3")
        assert.has_error(function () BuiltInFunctions.IPMatchFunc({"192.168.2.123", 128}) end, "Argument must be a string")

        assert.is.True(BuiltInFunctions.IPMatch("192.168.2.123", "192.168.2.0/24"))
        assert.is.True(BuiltInFunctions.IPMatch("192.168.2.123", "192.168.2.0/25"))
        assert.is.False(BuiltInFunctions.IPMatch("192.168.2.123", "192.168.2.0/26"))
        assert.is.True(BuiltInFunctions.IPMatch("192.168.2.123", "192.168.2.123"))
        assert.is.False(BuiltInFunctions.IPMatch("192.168.2.124", "192.168.2.123"))
        assert.is.False(BuiltInFunctions.IPMatch("192.166.2.123", "192.168.2.123"))
    end)
    
    it("keyMatch5 tests", function ()
        assert.has_error(function () BuiltInFunctions.keyMatch5Func({"/foo"}) end, "Expected 2 arguments, but got 1")
        assert.has_error(function () BuiltInFunctions.keyMatch5Func({"/foo/create/123", "/foo/*", "/foo/update/123"}) end, "Expected 2 arguments, but got 3")
        assert.has_error(function () BuiltInFunctions.keyMatch5Func({"/parent/123", true}) end, "Argument must be a string")
        
        assert.is.True(BuiltInFunctions.keyMatch5("/parent/child?status=1&type=2", "/parent/child"))
        assert.is.False(BuiltInFunctions.keyMatch5("/parent?status=1&type=2", "/parent/child"))

        assert.is.True(BuiltInFunctions.keyMatch5("/parent/child/?status=1&type=2", "/parent/child/"))
        assert.is.False(BuiltInFunctions.keyMatch5("/parent/child/?status=1&type=2", "/parent/child"))
        assert.is.False(BuiltInFunctions.keyMatch5("/parent/child?status=1&type=2", "/parent/child/"))
        
        assert.is.True(BuiltInFunctions.keyMatch5("/foo", "/foo"))
        assert.is.True(BuiltInFunctions.keyMatch5("/foo", "/foo*"))
        assert.is.False(BuiltInFunctions.keyMatch5("/foo", "/foo/*"))
        assert.is.False(BuiltInFunctions.keyMatch5("/foo/bar", "/foo"))
        assert.is.False(BuiltInFunctions.keyMatch5("/foo/bar", "/foo*"))
        assert.is.True(BuiltInFunctions.keyMatch5("/foo/bar", "/foo/*"))
        assert.is.False(BuiltInFunctions.keyMatch5("/foobar", "/foo"))
        assert.is.False(BuiltInFunctions.keyMatch5("/foobar", "/foo*"))
        assert.is.False(BuiltInFunctions.keyMatch5("/foobar", "/foo/*"))

        assert.is.False(BuiltInFunctions.keyMatch5("/", "/{resource}"))
        assert.is.True(BuiltInFunctions.keyMatch5("/resource1", "/{resource}"))
        assert.is.False(BuiltInFunctions.keyMatch5("/myid", "/{id}/using/{resId}"))
        assert.is.True(BuiltInFunctions.keyMatch5("/myid/using/myresid", "/{id}/using/{resId}"))
        
        assert.is.False(BuiltInFunctions.keyMatch5("/proxy/myid", "/proxy/{id}/*"))
        assert.is.True(BuiltInFunctions.keyMatch5("/proxy/myid/", "/proxy/{id}/*"))
        assert.is.True(BuiltInFunctions.keyMatch5("/proxy/myid/res", "/proxy/{id}/*"))
        assert.is.True(BuiltInFunctions.keyMatch5("/proxy/myid/res/res2", "/proxy/{id}/*"))
        assert.is.True(BuiltInFunctions.keyMatch5("/proxy/myid/res/res2/res3", "/proxy/{id}/*"))
        assert.is.False(BuiltInFunctions.keyMatch5("/proxy/", "/proxy/{id}/*"))
        
        assert.is.False(BuiltInFunctions.keyMatch5("/proxy/myid?status=1&type=2", "/proxy/{id}/*"))
        assert.is.True(BuiltInFunctions.keyMatch5("/proxy/myid/", "/proxy/{id}/*"))
        assert.is.True(BuiltInFunctions.keyMatch5("/proxy/myid/res?status=1&type=2", "/proxy/{id}/*"))
        assert.is.True(BuiltInFunctions.keyMatch5("/proxy/myid/res/res2?status=1&type=2", "/proxy/{id}/*"))
        assert.is.True(BuiltInFunctions.keyMatch5("/proxy/myid/res/res2/res3?status=1&type=2", "/proxy/{id}/*"))
        assert.is.False(BuiltInFunctions.keyMatch5("/proxy/", "/proxy/{id}/*"))
    end)
end)