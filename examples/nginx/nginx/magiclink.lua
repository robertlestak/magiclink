-- MagicLink Lua script for token cookie handling

-- Get auth token from response header
local auth_token = ngx.var.auth_token

if auth_token then
    ngx.log(ngx.DEBUG, "Found auth token in response header")
    
    -- Parse original request URL to extract token
    local request_uri = ngx.var.request_uri
    local contains_token = false
    
    -- Check if token is present in query parameters
    if string.find(request_uri, "magic_token=") then
        ngx.log(ngx.DEBUG, "Found magic_token in request URI: " .. request_uri)
        contains_token = true
        
        -- Set cookie with the token
        ngx.header["Set-Cookie"] = "magic_token=" .. auth_token .. "; Path=/; HttpOnly; Max-Age=900"
        ngx.log(ngx.DEBUG, "Set cookie: magic_token=" .. auth_token)
        
        -- Clean URL by removing magic_token parameter
        local clean_uri = string.gsub(request_uri, "([?&])magic_token=[^&]+&?", "%1")
        clean_uri = string.gsub(clean_uri, "[?&]$", "")
        
        -- Redirect to clean URL
        if clean_uri ~= request_uri then
            ngx.log(ngx.DEBUG, "Redirecting to clean URL: " .. clean_uri)
            ngx.header["Location"] = clean_uri
            ngx.status = 302
            ngx.exit(ngx.HTTP_MOVED_TEMPORARILY)
        end
    else
        ngx.log(ngx.DEBUG, "No token found in request URI")
    end
else
    ngx.log(ngx.DEBUG, "No auth token in response header")
end