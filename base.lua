local cjson = require("cjson")

local CommonEventFormatParser = {}

CommonEventFormatParser.new = function(conf)
    local self = {
        log_format = conf.log_format or "syslog",
        log_utc_offset = conf.log_utc_offset or nil,
        syslog_timestamp_format = conf.syslog_timestamp_format or '\\w{3}\\s+\\d{1,2}\\s\\d{2}:\\d{2}:\\d{2}',
        syslog_timestamp_format_5424 = conf.syslog_timestamp_format_5424 or '\\d{4}[-]\\d{2}[-]\\d{2}[T]\\d{2}[:]\\d{2}[:]\\d{2}(?:\\.\\d{1,6})?(?:[+-]\\d{2}[:]\\d{2}|Z)',
        cef_version = conf.cef_version or 0,
        parse_strict_mode = conf.parse_strict_mode or true,
        cef_keyfilename = conf.cef_keyfilename or 'config/cef_version_0_keys.yaml',
        output_raw_field = conf.output_raw_field or false
    }

    self.REGEXP_DETECT_RFC5424 = '^[1-9]\\d{0,2}'
    self.REGEXP_DETECT_PLAIN = '^CEF:'
    self.MAPPINGS = {
        ["act"] = "deviceAction", ["app"] = "applicationProtocol", ["c6a1"] = "deviceCustomIPv6Address1",
        ["c6a1Label"] = "deviceCustomIPv6Address1Label", ["c6a2"] = "deviceCustomIPv6Address2",
        ["c6a2Label"] = "deviceCustomIPv6Address2Label", ["c6a3"] = "deviceCustomIPv6Address3",
        ["c6a3Label"] = "deviceCustomIPv6Address3Label", ["c6a4"] = "deviceCustomIPv6Address4",
        ["c6a4Label"] = "deviceCustomIPv6Address4Label", ["cat"] = "deviceEventCategory",
        ["cfp1"] = "deviceCustomFloatingPoint1", ["cfp1Label"] = "deviceCustomFloatingPoint1Label",
        ["cfp2"] = "deviceCustomFloatingPoint2", ["cfp2Label"] = "deviceCustomFloatingPoint2Label",
        ["cfp3"] = "deviceCustomFloatingPoint3", ["cfp3Label"] = "deviceCustomFloatingPoint3Label",
        ["cfp4"] = "deviceCustomFloatingPoint4", ["cfp4Label"] = "deviceCustomFloatingPoint4Label",
        ["cn1"] = "deviceCustomNumber1", ["cn1Label"] = "deviceCustomNumber1Label",
        ["cn2"] = "deviceCustomNumber2", ["cn2Label"] = "deviceCustomNumber2Label",
        ["cn3"] = "deviceCustomNumber3", ["cn3Label"] = "deviceCustomNumber3Label",
        ["cnt"] = "baseEventCount", ["cs1"] = "deviceCustomString1", ["cs1Label"] = "deviceCustomString1Label",
        ["cs2"] = "deviceCustomString2", ["cs2Label"] = "deviceCustomString2Label",
        ["cs3"] = "deviceCustomString3", ["cs3Label"] = "deviceCustomString3Label",
        ["cs4"] = "deviceCustomString4", ["cs4Label"] = "deviceCustomString4Label",
        ["cs5"] = "deviceCustomString5", ["cs5Label"] = "deviceCustomString5Label",
        ["cs6"] = "deviceCustomString6", ["cs6Label"] = "deviceCustomString6Label",
        ["dhost"] = "destinationHostName", ["dmac"] = "destinationMacAddress",
        ["dntdom"] = "destinationNtDomain", ["dpid"] = "destinationProcessId",
        ["dpriv"] = "destinationUserPrivileges", ["dproc"] = "destinationProcessName",
        ["dpt"] = "destinationPort", ["dst"] = "destinationAddress", ["duid"] = "destinationUserId",
        ["duser"] = "destinationUserName", ["dvc"] = "deviceAddress", ["dvchost"] = "deviceHostName",
        ["dvcpid"] = "deviceProcessId", ["end"] = "endTime", ["fname"] = "fileName", ["fsize"] = "fileSize",
        ["in"] = "bytesIn", ["msg"] = "message", ["out"] = "bytesOut", ["outcome"] = "eventOutcome",
        ["proto"] = "transportProtocol", ["request"] = "requestUrl", ["rt"] = "deviceReceiptTime",
        ["shost"] = "sourceHostName", ["smac"] = "sourceMacAddress", ["sntdom"] = "sourceNtDomain",
        ["spid"] = "sourceProcessId", ["spriv"] = "sourceUserPrivileges", ["sproc"] = "sourceProcessName",
        ["spt"] = "sourcePort", ["src"] = "sourceAddress", ["start"] = "startTime", ["suid"] = "sourceUserId",
        ["suser"] = "sourceUserName", ["ahost"] = "agentHost", ["art"] = "agentReceiptTime",
        ["at"] = "agentType", ["aid"] = "agentId", ["_cefVer"] = "cefVersion", ["agt"] = "agentAddress",
        ["av"] = "agentVersion", ["atz"] = "agentTimeZone", ["dtz"] = "destinationTimeZone",
        ["slong"] = "sourceLongitude", ["slat"] = "sourceLatitude",
        ["dlong"] = "destinationLongitude", ["dlat"] = "destinationLatitude",
        ["catdt"] = "categoryDeviceType", ["mrt"] = "managerReceiptTime", ["amac"] = "agentMacAddress"
    }

    self.EXTENSION_VALUE_ESCAPE_CAPTURE = /\\([\\=])/
    self.EXTENSION_KEY_PATTERN = /(?:\w+(?:\.[^\.=\s\|\\\[\]]+)*(?:\[[0-9]+\])?(?==))/
    self.EXTENSION_KEY_ARRAY_CAPTURE = /^([^\[\]]+)((?:\[[0-9]+\])+)/
    self.EXTENSION_VALUE_PATTERN = /(?:\S|\s++(?!#{self.EXTENSION_KEY_PATTERN}=))*/
    self.EXTENSION_KEY_VALUE_SCANNER = /(#{self.EXTENSION_KEY_PATTERN})=(#{self.EXTENSION_VALUE_PATTERN})\s*/

    self.valid_format_regexp = CommonEventFormatParser.create_valid_format_regexp(self)
    self.valid_format_regexp_5424 = CommonEventFormatParser.create_valid_format_regexp_5424(self)
    self.valid_format_regexp_plain = CommonEventFormatParser.create_valid_format_regexp_plain(self)
    self.utc_offset = CommonEventFormatParser.get_utc_offset(self, self.log_utc_offset)
    self.keys_array = {}

    if self.parse_strict_mode then
        local success, yaml_fieldinfo
        if string.match(self.cef_keyfilename, '^/') then
            success, yaml_fieldinfo = pcall(cjson.decode, io.open(self.cef_keyfilename):read('*a'))
        else
            success, yaml_fieldinfo = pcall(cjson.decode, io.open(fluentd_config.localize_file_path(self.cef_keyfilename)):read('*a'))
        end

        if success then
            for key, value in pairs(yaml_fieldinfo) do
                for _, v in pairs(value) do
                    table.insert(self.keys_array, v)
                end
            end
            print("running with strict mode, " .. #self.keys_array .. " keys are valid.")
        else
            self.parse_strict_mode = false
            print("running without strict mode")
            print("running without strict mode because of the following error:")
            print(tostring(yaml_fieldinfo))
        end
    end

    return setmetatable(self, {__index = CommonEventFormatParser})
end

function CommonEventFormatParser:parse(text)
    if text == nil or text == "" then
        return nil, nil
    end

    text = text:gsub('�', '?')
    local record = {}
    local record_overview
    if string.match(text, self.REGEXP_DETECT_RFC5424) then
        record_overview = self.valid_format_regexp_5424:match(text)
    elseif string.match(text, self.REGEXP_DETECT_PLAIN) then
        record_overview = self.valid_format_regexp_plain:match(text)
    else
        record_overview = self.valid_format_regexp:match(text)
    end

    if not record_overview then
        return os.time(), { raw = text }
    end

    local time = CommonEventFormatParser.get_unixtime_with_utc_offset(self, record_overview.syslog_timestamp, self.utc_offset)
    for key in record_overview:names() do
        record[key] = record_overview[key]
    end
    local text_cef_extension = record_overview.cef_extension
    record.cef_extension = nil

    if text_cef_extension then
        local record_cef_extension = self:parse_cef_extension(text_cef_extension)
        for k, v in pairs(record_cef_extension) do
            record[k] = v
        end
    end

    if self.output_raw_field then
        record.raw = text
    end

    return time, record
end

function CommonEventFormatParser:get_utc_offset(text)
    local utc_offset
    local success, err
    if text then
        success, utc_offset = pcall(os.date, '!%:z', os.time(), text)
    else
        utc_offset = os.date('!%:z', os.time())
    end

    if success then
        print("utc_offset: " .. utc_offset)
    else
        utc_offset = os.date('!%:z', os.time())
        print(tostring(err) .. ", use localtime")
        print("utc_offset: " .. utc_offset)
    end

    return utc_offset
end

function CommonEventFormatParser:create_valid_format_regexp()
    local syslog_header = string.format(
        "(?<syslog_timestamp>%s)\\s" ..
        "(?<syslog_hostname>\\S+)\\s" ..
        "(?<syslog_tag>\\S*)\\s*",
        self.syslog_timestamp_format
    )

    local cef_header = string.format(
        "CEF:(?<cef_version>%d)\\|" ..
        "(?<cef_device_vendor>[^|]*)\\|" ..
        "(?<cef_device_product>[^|]*)\\|" ..
        "(?<cef_device_version>[^|]*)\\|" ..
        "(?<cef_device_event_class_id>[^|]*)\\|" ..
        "(?<cef_name>[^|]*)\\|" ..
        "(?<cef_severity>[^|]*)",
        self.cef_version
    )

    return "^" ..
           syslog_header ..
           "(?:\239\187\191)?" ..
           cef_header .. "\\|" ..
           "(?<cef_extension>.*)" ..
           "$"
end

function CommonEventFormatParser:create_valid_format_regexp_5424()
    local syslog_header = string.format(
        "(?:[1-9])\\s" ..
        "(?<syslog_timestamp>%s)\\s" ..
        "(?<syslog_hostname>\\S+)\\s" ..
        "(?<syslog_tag>\\S+)\\s" ..
        "(?<pid>\\S+)\\s" ..
        "(?<msgid>\\S+)\\s" ..
        "(?<extradata>(?:\\-|(?:\\[.*?(?<!\\\\)\\])+))\\s",
        self.syslog_timestamp_format_5424
    )

    local cef_header = string.format(
        "CEF:(?<cef_version>%d)\\|" ..
        "(?<cef_device_vendor>[^|]*)\\|" ..
        "(?<cef_device_product>[^|]*)\\|" ..
        "(?<cef_device_version>[^|]*)\\|" ..
        "(?<cef_device_event_class_id>[^|]*)\\|" ..
        "(?<cef_name>[^|]*)\\|" ..
        "(?<cef_severity>[^|]*)",
        self.cef_version
    )

    return "^" ..
           syslog_header ..
           cef_header .. "\\|" ..
           "(?<cef_extension>.*)" ..
           "$"
end

function CommonEventFormatParser:create_valid_format_regexp_plain()
    local cef_header = string.format(
        "CEF:(?<cefVersion>%d)\\|" ..
        "(?<deviceVendor>[^|]*)\\|" ..
        "(?<deviceProduct>[^|]*)\\|" ..
        "(?<deviceVersion>[^|]*)\\|" ..
        "(?<deviceEventClassId>[^|]*)\\|" ..
        "(?<name>[^|]*)\\|" ..
        "(?<severity>[^|]*)",
        self.cef_version
    )

    return "^" ..
           cef_header .. "\\|" ..
           "(?<cef_extension>.*)" ..
           "$"
end

function CommonEventFormatParser:get_unixtime_with_utc_offset(timestamp, utc_offset)
    local unixtime
    local success, err
    if string.match(timestamp, '[-+]%d%d:%d%d$') then
        success, unixtime = pcall(os.time, os.date('!*t', os.time()))
    else
        success, unixtime = pcall(os.time, os.date('!*t', os.time()) .. ' ' .. utc_offset)
    end

    if not success then
        unixtime = os.time()
        print(tostring(err))
    end

    return unixtime
end

function CommonEventFormatParser:parse_cef_extension(text)
    local record = {}
    if self.parse_strict_mode then
        return self:parse_cef_extension_with_strict_mode(text)
    else
        return self:parse_cef_extension_without_strict_mode(text)
    end
end

function CommonEventFormatParser:parse_cef_extension_with_strict_mode(text)
    local record = {}
    local last_valid_key_name
    for key, value in string.gmatch(text, self.key_value_format_regexp) do
        if self.keys_array[key] then
            record[key] = value
            if last_valid_key_name then
                record[last_valid_key_name] = record[last_valid_key_name]:gsub('%s*$', '')
            end
            last_valid_key_name = key
        else
            last_valid_key_name = key
            record[last_valid_key_name] = value
        end
    end
    return record
end

function CommonEventFormatParser:parse_cef_extension_without_strict_mode(text)
    local record = {}
    for extension_field_key, raw_extension_field_value in string.gmatch(text, self.EXTENSION_KEY_VALUE_SCANNER) do
        extension_field_key = self.MAPPINGS[extension_field_key] or extension_field_key
        if string.match(extension_field_key, '%]') then
            extension_field_key = extension_field_key:gsub(self.EXTENSION_KEY_ARRAY_CAPTURE, '[%1]%2')
        end
        extension_field_value = raw_extension_field_value:gsub(self.EXTENSION_VALUE_ESCAPE_CAPTURE, '%1')
        record[extension_field_key] = extension_field_value:gsub('%s*$', '')
    end
    return record
end

return CommonEventFormatParser
