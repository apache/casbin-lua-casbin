package = "casbin"
version = "1.47.0-1"
source = {
   url = "https://downloads.apache.org/incubator/casbin/lua/1.47.0/apache-casbin-lua-1.47.0-incubating-src.tar.gz",
   dir = "apache-casbin-lua-1.47.0-incubating-src",
}
description = {
   summary = "Apache Casbin for Lua (incubating): ACL, RBAC and ABAC authorization",
   detailed = [[
Apache Casbin is an effort undergoing incubation at The Apache Software
Foundation (ASF), sponsored by the Apache Incubator. Incubation is required
of all newly accepted projects until a further review indicates that the
infrastructure, communications, and decision making process have stabilized
in a manner consistent with other successful ASF projects. While incubation
status is not necessarily a reflection of the completeness or stability of
the code, it does indicate that the project has yet to be fully endorsed by
the ASF.
   ]],
   homepage = "https://github.com/apache/casbin-lua-casbin",
   license = "Apache License 2.0",
   maintainer = "Apache Casbin <dev@casbin.apache.org>"
}
dependencies = {
   "lua >= 5.1",
   "lualogging >= 1.5.1",
   "lrexlib-pcre2 >= 2.9.2",
   "luaposix = 35.1-1"
}
build = {
   type = "builtin",
   copy_directories = {"doc"},
   modules = {
      ["casbin"] = "casbin.lua",
      ["src.config.Config"] = "src/config/Config.lua",
      ["src.effect.DefaultEffector"] = "src/effect/DefaultEffector.lua",
      ["src.effect.Effect"] = "src/effect/Effect.lua",
      ["src.effect.Effector"] = "src/effect/Effector.lua",
      ["src.main.CoreEnforcer"] = "src/main/CoreEnforcer.lua",
      ["src.main.InternalEnforcer"] = "src/main/InternalEnforcer.lua",
      ["src.main.ManagementEnforcer"] = "src/main/ManagementEnforcer.lua",
      ["src.main.Enforcer"] = "src/main/Enforcer.lua",
      ["src.main.CachedEnforcer"] = "src/main/CachedEnforcer.lua",
      ["src.model.Assertion"] = "src/model/Assertion.lua",
      ["src.model.Model"] = "src/model/Model.lua",
      ["src.model.Policy"] = "src/model/Policy.lua",
      ["src.model.FunctionMap"] = "src/model/FunctionMap.lua",
      ["src.persist.cache.Cache"] = "src/persist/cache/Cache.lua",
      ["src.persist.cache.DefaultCache"] = "src/persist/cache/DefaultCache.lua",
      ["src.persist.UpdateAdapter"] = "src/persist/UpdateAdapter.lua",
      ["src.persist.Adapter"] = "src/persist/Adapter.lua",
      ["src.persist.BatchAdapter"] = "src/persist/BatchAdapter.lua",
      ["src.persist.FilteredAdapter"] = "src/persist/FilteredAdapter.lua",
      ["src.persist.file_adapter.FileAdapter"] = "src/persist/file_adapter/FileAdapter.lua",
      ["src.persist.file_adapter.Filter"] = "src/persist/file_adapter/Filter.lua",
      ["src.persist.file_adapter.FilteredAdapter"] = "src/persist/file_adapter/FilteredAdapter.lua",
      ["src.persist.database_adapter.DatabaseAdapter"] = "src/persist/database_adapter/DatabaseAdapter.lua",
      ["src.persist.Watcher"] = "src/persist/Watcher.lua",
      ["src.persist.WatcherEx"] = "src/persist/WatcherEx.lua",
      ["src.persist.WatcherUpdatable"] = "src/persist/WatcherUpdatable.lua",
      ["src.persist.Dispatcher"] = "src/persist/Dispatcher.lua",
      ["src.rbac.DefaultRoleManager"] = "src/rbac/DefaultRoleManager.lua",
      ["src.rbac.Role"] = "src/rbac/Role.lua",
      ["src.rbac.RoleManager"] = "src/rbac/RoleManager.lua",
      ["src.util.Util"] = "src/util/Util.lua",
      ["src.util.BuiltInFunctions"] = "src/util/BuiltInFunctions.lua",
      ["src.util.Log"] = "src/util/Log.lua",
      ["modules.luaxp"] = "modules/luaxp.lua"
   }
}