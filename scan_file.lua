
--[[
	dec to 32 bytes hex 
	13 to 0000000d
]]
local function decimalToHex(num)
    if num == 0 then
        return -1
    end
    local neg = false
    if num < 0 then
        neg = true
        num = num * -1
    end

    local hexstr = "0123456789ABCDEF"
    local result = ""
    local len    = 0

    while num > 0 do
        local n = num %  16
        len 	= len + 1
        result 	= string.sub(hexstr, n + 1, n + 1) .. result
        num 	= math.floor(num / 16)
    end

    for i=len+1, 8, 1 do
        result = "0"..result
    end

    return result
end



--[[
	send file to clamav
	@param retuen 1 virus found
	@param return 0 virus not found
]]
local function check_file(data)

	lenHexStr = decimalToHex(string.len(data))
    lenStr = ""
    for i = 1, string.len(lenHexStr), 2  do
        lenStr = lenStr .. string.char("0x"..string.sub(lenHexStr, i, i+1))
    end

    local host, port 	= "127.0.0.1", 3310
    local socket 		= require("socket")
    local tcp 			= assert(socket.tcp())

    tcp:connect(host, port);
    tcp:send("zINSTREAM\0");
    tcp:send(lenStr);
    tcp:send(data);

    tcp:send(string.char(0x00).. string.char(0x00).. string.char(0x00).. string.char( 0x00 ));
	-- tcp:send("PING")
    while true do
        local s, status, partial = tcp:receive()

		tcp:close()
		ngx.say(partial)
		if string.sub(partial, 0, 10) == "stream: OK" then
			return 0
		end
		-- virus
		return 1
        --if status == "closed" then 
			-- return 0
		--	return 0
		--end
		
    end

	-- ::close_tcp::
    -- 	tcp:close()
end




--[[
	proces file from buffer
]]
local function  process_file (file)
	-- check if is file?
	is_file = 0
	for line in file:gmatch("([^\n]*)\n?") do
		if ( string.len(line) >=  string.len("Content-Type:") 
			 and "Content-Type:" == string.sub(line, 0, string.len("Content-Type:") )) then

			is_file = 1
			break
			
		end
	end

	
	if (is_file == 0 ) then
		ngx.say("data is not file")
		ngx.say(line)
		goto continue
	end

	-- get body
	idx = 0
	is_file = 0
	for line in file:gmatch("([^\n]*)\n?") do
		idx	= idx + string.len(line) + 1
		if (string.byte(line) == 13 ) then
			is_file = 1
			break
		end
	end

	if (is_file == 0 ) then
		ngx.say("wrong form-data format [0x0d]")
		goto continue
	end
	
	-- data for clamav
	file = string.sub(file, idx + 1, string.len(file) - 1)  

	if ( check_file(file) == 1 ) then
		return 1
	end

	::continue::
	return 0
end


local function process_from_buffer(data)
	
	local boundary		= ""
	local boundary_end	= ""
	local flag	   		= 0
	local i				= 0
	local idxs			= {}
	local idx	   		= 0
	local format	   	= 0

	-- split by line
	-- search boundary
	for line in data:gmatch("([^\n]*)\n?") do
		idx	= idx + string.len(line) + 1  -- for \n

		if ( flag == 0 ) then
			boundary	= string.sub(line, 1,  string.len(line) -1  )
			boundary_end= string.sub(line, 1,  string.len(line) -1) .. "-" .. "-"
			flag 	= 1
			goto update_indexes
		end
		
		if ( string.len(line) >= string.len(boundary_end) and string.match(line, boundary_end) ) then	
			-- format is corect?
			format = 1  

			goto update_indexes
		end

		if ( string.len(line) >= string.len(boundary) and string.match(line, boundary) ) then	
			goto update_indexes
		end
		
		goto continue
		
		::update_indexes::
			idxs[i] = idx
			i 		= i +1
			
		
		::continue::
	end
	
	if format == 0 then
		ngx.say ("not form-data format")
		return 0
	end

	-- extract files
	local file 		= ""
	local is_file 	= 0 
	for j=0, i-2, 1 do
		ngx.say(idxs[j])
		if (j == i - 2) then
			file = string.sub(data, idxs[j], idxs[j+1] - string.len(boundary) - 5 )
		else 	
			file = string.sub(data, idxs[j], idxs[j+1] - string.len(boundary) - 3 )  
		end

		if ( process_file(file) == 1) then
			return 1
		end
	
	end

	return 0

end



--[[ 
	-- explicitly read the req body
]]
ngx.req.read_body()  

local data = ngx.req.get_body_data()

if data then
	-- if file in buffer
	if ( process_from_buffer(data) == 1) then
		-- virus found
		ngx.say("virus")
	else
		-- virus not found
		ngx.say("non-virus")
	end
else
	--	body may get buffered in a temp file:
	--  > client_body_buffer_size
	ngx.say("file is to large")
end








