-- 44790/22719 业务面：调用 r:parsebody() 的 Lua handler
function handle(r)
    r:parsebody()
    r.content_type = "text/plain"
    r:puts("PARSEBODY OK\n")
    return apache2.OK
end
