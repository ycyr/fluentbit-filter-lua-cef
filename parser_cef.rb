# -*- coding: utf-8

require 'fluent/log'
require 'fluent/plugin/parser'
require 'time'
require 'yaml'
require 'charlock_holmes'

module Fluent
  module Plugin
    class CommonEventFormatParser < Parser
      Fluent::Plugin.register_parser("cef", self)

      REGEXP_DETECT_RFC5424 = /^[1-9]\d{0,2}/
      REGEXP_DETECT_PLAIN = /^CEF:/
      MAPPINGS = { "act" => "deviceAction", "app" => "applicationProtocol", "c6a1" => "deviceCustomIPv6Address1", "c6a1Label" => "deviceCustomIPv6Address1Label", "c6a2" => "deviceCustomIPv6Address2", "c6a2Label" => "deviceCustomIPv6Address2Label", "c6a3" => "deviceCustomIPv6Address3", "c6a3Label" => "deviceCustomIPv6Address3Label", "c6a4" => "deviceCustomIPv6Address4", "c6a4Label" => "deviceCustomIPv6Address4Label", "cat" => "deviceEventCategory", "cfp1" => "deviceCustomFloatingPoint1", "cfp1Label" => "deviceCustomFloatingPoint1Label", "cfp2" => "deviceCustomFloatingPoint2", "cfp2Label" => "deviceCustomFloatingPoint2Label", "cfp3" => "deviceCustomFloatingPoint3", "cfp3Label" => "deviceCustomFloatingPoint3Label", "cfp4" => "deviceCustomFloatingPoint4", "cfp4Label" => "deviceCustomFloatingPoint4Label", "cn1" => "deviceCustomNumber1", "cn1Label" => "deviceCustomNumber1Label", "cn2" => "deviceCustomNumber2", "cn2Label" => "deviceCustomNumber2Label", "cn3" => "deviceCustomNumber3", "cn3Label" => "deviceCustomNumber3Label", "cnt" => "baseEventCount", "cs1" => "deviceCustomString1", "cs1Label" => "deviceCustomString1Label", "cs2" => "deviceCustomString2", "cs2Label" => "deviceCustomString2Label", "cs3" => "deviceCustomString3", "cs3Label" => "deviceCustomString3Label", "cs4" => "deviceCustomString4", "cs4Label" => "deviceCustomString4Label", "cs5" => "deviceCustomString5", "cs5Label" => "deviceCustomString5Label", "cs6" => "deviceCustomString6", "cs6Label" => "deviceCustomString6Label", "dhost" => "destinationHostName", "dmac" => "destinationMacAddress", "dntdom" => "destinationNtDomain", "dpid" => "destinationProcessId", "dpriv" => "destinationUserPrivileges", "dproc" => "destinationProcessName", "dpt" => "destinationPort", "dst" => "destinationAddress", "duid" => "destinationUserId", "duser" => "destinationUserName", "dvc" => "deviceAddress", "dvchost" => "deviceHostName", "dvcpid" => "deviceProcessId", "end" => "endTime", "fname" => "fileName", "fsize" => "fileSize", "in" => "bytesIn", "msg" => "message", "out" => "bytesOut", "outcome" => "eventOutcome", "proto" => "transportProtocol", "request" => "requestUrl", "rt" => "deviceReceiptTime", "shost" => "sourceHostName", "smac" => "sourceMacAddress", "sntdom" => "sourceNtDomain", "spid" => "sourceProcessId", "spriv" => "sourceUserPrivileges", "sproc" => "sourceProcessName", "spt" => "sourcePort", "src" => "sourceAddress", "start" => "startTime", "suid" => "sourceUserId", "suser" => "sourceUserName", "ahost" => "agentHost", "art" => "agentReceiptTime", "at" => "agentType", "aid" => "agentId", "_cefVer" => "cefVersion", "agt" => "agentAddress", "av" => "agentVersion", "atz" => "agentTimeZone", "dtz" => "destinationTimeZone", "slong" => "sourceLongitude", "slat" => "sourceLatitude", "dlong" => "destinationLongitude", "dlat" => "destinationLatitude", "catdt" => "categoryDeviceType", "mrt" => "managerReceiptTime", "amac" => "agentMacAddress" }

      #Based on logstash codec cef 6.1.2

      # Cache of a gsub pattern that matches a backslash-escaped backslash or backslash-escaped equals, _capturing_ the escaped character
      EXTENSION_VALUE_ESCAPE_CAPTURE = /\\([\\=])/

      # While the original CEF spec calls out that extension keys must be alphanumeric and must not contain spaces,
      # in practice many "CEF" producers like the Arcsight smart connector produce non-legal keys including underscores,
      # commas, periods, and square-bracketed index offsets.
      #
      # To support this, we look for a specific sequence of characters that are followed by an equals sign. This pattern
      # will correctly identify all strictly-legal keys, and will also match those that include a dot-joined "subkeys" and
      # square-bracketed array indexing
      #
      # That sequence must begin with one or more `\w` (word: alphanumeric + underscore), which _optionally_ may be followed
      # by one or more "subkey" sequences and an optional square-bracketed index.
      #
      # To be understood by this implementation, a "subkey" sequence must consist of a literal dot (`.`) followed by one or
      # more characters that do not convey semantic meaning within CEF (e.g., literal-dot (`.`), literal-equals (`=`),
      # whitespace (`\s`), literal-pipe (`|`), literal-backslash ('\'), or literal-square brackets (`[` or `]`)).
      EXTENSION_KEY_PATTERN = /(?:\w+(?:\.[^\.=\s\|\\\[\]]+)*(?:\[[0-9]+\])?(?==))/



      # Some CEF extension keys seen in the wild use an undocumented array-like syntax that may not be compatible with
      # the Event API's strict-mode FieldReference parser (e.g., `fieldname[0]`).
      # Cache of a `String#sub` pattern matching array-like syntax and capturing both the base field name and the
      # array-indexing portion so we can convert to a valid FieldReference (e.g., `[fieldname][0]`).
      EXTENSION_KEY_ARRAY_CAPTURE = /^([^\[\]]+)((?:\[[0-9]+\])+)$/ # '[\1]\2'

      # In extensions, spaces may be included in an extension value without any escaping,
      # so an extension value is a sequence of zero or more:
      # - non-whitespace character; OR
      # - runs of whitespace that are NOT followed by something that looks like a key-equals sequence
      EXTENSION_VALUE_PATTERN = /(?:\S|\s++(?!#{EXTENSION_KEY_PATTERN}=))*/

      # Cache of a scanner pattern that _captures_ extension field key/value pairs
      EXTENSION_KEY_VALUE_SCANNER = /(#{EXTENSION_KEY_PATTERN})=(#{EXTENSION_VALUE_PATTERN})\s*/


      config_param :log_format, :string, :default => "syslog"
      config_param :log_utc_offset, :string, :default => nil
      config_param :syslog_timestamp_format, :string, :default => '\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}'
      config_param :syslog_timestamp_format_5424, :string, :default => '\d{4}[-]\d{2}[-]\d{2}[T]\d{2}[:]\d{2}[:]\d{2}(?:\.\d{1,6})?(?:[+-]\d{2}[:]\d{2}|Z)'
      config_param :cef_version, :integer, :default => 0
      config_param :parse_strict_mode, :bool, :default => true
      config_param :cef_keyfilename, :string, :default => 'config/cef_version_0_keys.yaml'
      config_param :output_raw_field, :bool, :default => false

      def configure(conf)
        super
        @key_value_format_regexp = /([^\s=]+)=(.*?)(?:(?=[^\s=]+=)|\z)/
        @valid_format_regexp = create_valid_format_regexp
        @valid_format_regexp_5424 = create_valid_format_regexp_5424
        @valid_format_regexp_plain = create_valid_format_regexp_plain
        @utc_offset = get_utc_offset(@log_utc_offset)
        begin
          $log.trace(@valid_format_regexp)
          $log.trace(@valid_format_regexp_5424)
          $log.trace(@valid_format_regexp_plain)
          if @parse_strict_mode
            if @cef_keyfilename =~ /^\//
              yaml_fieldinfo = YAML.load_file(@cef_keyfilename)
            else
              yaml_fieldinfo = YAML.load_file("#{File.dirname(File.expand_path(__FILE__))}/#{@cef_keyfilename}")
            end
            @keys_array = []
            yaml_fieldinfo.each {|_key, value| @keys_array.concat(value) }
            $log.info "running with strict mode, #{@keys_array.length} keys are valid."
          else
            $log.info "running without strict mode"
          end
        rescue => e
          @parse_strict_mode = false
          $log.warn "running without strict mode because of the following error"
          $log.warn "#{e.message}"
          
        end
      end

      def parse(text)
        if text.nil? || text.empty?
          yield nil, nil
          return
        end
        log.trace(text)
        detection = CharlockHolmes::EncodingDetector.detect(text)
        log.trace(detection)
        utf8_encoded_content = CharlockHolmes::Converter.convert text, detection[:encoding], 'UTF-8'
        utf8_encoded_content.force_encoding("utf-8")
        #utf8_encoded_content_chomp = utf8_encoded_content.delete!("\r\n")
        #utf8_encoded_content.delete!("\r\n")
        replaced_text = utf8_encoded_content.delete("\r\n").scrub('?')
        #text.force_encoding("utf-8")
        #replaced_text = text.scrub('?')
        record = {}
        if REGEXP_DETECT_RFC5424.match(text)
          record_overview = @valid_format_regexp_5424.match(replaced_text)
          log.trace "match 5424"
        elsif REGEXP_DETECT_PLAIN.match(text)
           record_overview = @valid_format_regexp_plain.match(replaced_text)
           log.trace "match Plain CEF"
        else
          record_overview = @valid_format_regexp.match(replaced_text)
          log.trace "match 3164"
        end
        if record_overview.nil?
          yield Engine.now, { "raw" => replaced_text }
            log.trace "Matching Failed"
          return
        end
        
        unless REGEXP_DETECT_PLAIN.match(text)
          time = get_unixtime_with_utc_offset(record_overview["syslog_timestamp"], @utc_offset)
        end
            
    
        begin
          log.trace(record_overview)
          record_overview.names.each {|key| record[key] = record_overview[key] }
          text_cef_extension = record_overview["cef_extension"]
          record.delete("cef_extension")
        rescue
          yield Engine.now, { "raw" => replaced_text }
          log.trace "Parsing CEF Failed"
          return
        end
        unless text_cef_extension.nil?
          record_cef_extension = parse_cef_extension(text_cef_extension)
          record.merge!(record_cef_extension)
        end
        record["raw"] = replaced_text if @output_raw_field
        yield time, record
        return
      end

      private

      def get_utc_offset(text)
        utc_offset = nil
        begin
          utc_offset = Time.new.localtime(text).strftime("%:z")
          $log.info "utc_offset: #{utc_offset}"
        rescue => e
          utc_offset = Time.new.localtime.strftime("%:z")
          $log.info "#{e.message}, use localtime"
          $log.info "utc_offset: #{utc_offset}"
        end
        return utc_offset
      end


      #def create_valid_format_regexp_plain()
      #  case @log_format
      #  when "syslog"
      #    cef_header = /
      #      CEF:(?<cef_version>#{@cef_version})\|
      #      (?<cef_device_vendor>[^|]*)\|
      #      (?<cef_device_product>[^|]*)\|
      #      (?<cef_device_version>[^|]*)\|
      #      (?<cef_device_event_class_id>[^|]*)\|
      #      (?<cef_name>[^|]*)\|
      #      (?<cef_severity>[^|]*)
      #    /x
      #    valid_format_regexp_plain= /
      #        \A
      #          #{cef_header}\|
      #          (?<cef_extension>.*)
      #        \z
      #      /x
      #  else
      #    raise Fluent::ConfigError, "#{@log_format} is unknown format"
      #   end
      #  return Regexp.new(valid_format_regexp_plain)
      #end




      def create_valid_format_regexp_plain()
        case @log_format
        when "syslog"
          cef_header = /
            CEF:(?<cefVersion>#{@cef_version})\|
            (?<deviceVendor>[^|]*)\|
            (?<deviceProduct>[^|]*)\|
            (?<deviceVersion>[^|]*)\|
            (?<deviceEventClassId>[^|]*)\|
            (?<name>[^|]*)\|
            (?<severity>[^|]*)
          /x
          valid_format_regexp_plain= /
              \A
                #{cef_header}\|
                (?<cef_extension>.*)
              \z
            /x
        else
          raise Fluent::ConfigError, "#{@log_format} is unknown format"
        end
        return Regexp.new(valid_format_regexp_plain)
      end


      def create_valid_format_regexp()
        case @log_format
        when "syslog"
          syslog_header = /
              (?<syslog_timestamp>#{@syslog_timestamp_format})\s
              (?<syslog_hostname>\S+)\s
              (?<syslog_tag>\S*)\s*
            /x
          cef_header = /
            CEF:(?<cef_version>#{@cef_version})\|
            (?<cef_device_vendor>[^|]*)\|
            (?<cef_device_product>[^|]*)\|
            (?<cef_device_version>[^|]*)\|
            (?<cef_device_event_class_id>[^|]*)\|
            (?<cef_name>[^|]*)\|
            (?<cef_severity>[^|]*)
          /x
          valid_format_regexp = /
              \A
                #{syslog_header}
                (?:\u{feff})?
                #{cef_header}\|
                (?<cef_extension>.*)
              \z
            /x
        else
          raise Fluent::ConfigError, "#{@log_format} is unknown format"
        end
        return Regexp.new(valid_format_regexp)
      end

      def create_valid_format_regexp_5424()
        case @log_format
        when "syslog"
          syslog_header = /
            (?:[1-9])\s
            (?<syslog_timestamp>#{@syslog_timestamp_format_5424})\s
            (?<syslog_hostname>\S+)\s
            (?<syslog_tag>\S+)\s
            (?<pid>\S+)\s
            (?<msgid>\S+)\s
            (?<extradata>(?:\-|(?:\[.*?(?<!\\)\])+))\s
          /x
          cef_header = /
            CEF:(?<cef_version>#{@cef_version})\|
            (?<cef_device_vendor>[^|]*)\|
            (?<cef_device_product>[^|]*)\|
            (?<cef_device_version>[^|]*)\|
            (?<cef_device_event_class_id>[^|]*)\|
            (?<cef_name>[^|]*)\|
            (?<cef_severity>[^|]*)
          /x
          valid_format_regexp_5424 = /
              \A
                #{syslog_header}
                #{cef_header}\|
                (?<cef_extension>.*)
              \z
            /x
        else
          raise Fluent::ConfigError, "#{@log_format} is unknown format"
        end
        return Regexp.new(valid_format_regexp_5424)
      end

      def get_unixtime_with_utc_offset(timestamp, utc_offset)
        unixtime = nil
        begin
          if timestamp =~ /[-+]\d{2}:?\d{2}\z/
            unixtime = Time.parse(timestamp).to_i
          else
            unixtime = Time.parse("#{timestamp} #{utc_offset}").to_i
          end
        rescue
          unixtime = Engine.now
        end
        return unixtime
      end

      def parse_cef_extension(text)
        if @parse_strict_mode == true
          return parse_cef_extension_with_strict_mode(text)
        else
          return parse_cef_extension_without_strict_mode(text)
        end
      end

      def parse_cef_extension_with_strict_mode(text)
        record = {}
        begin
          last_valid_key_name = nil
          text.scan(@key_value_format_regexp) do |key, value|
            if @keys_array.include?(key)
              record[key] = value
              record[last_valid_key_name].rstrip! unless last_valid_key_name.nil?
              last_valid_key_name = key
            else
              record[last_valid_key_name].concat("#{key}=#{value}")
            end
          end
        rescue
          return {}
        end
        return record
      end

      def parse_cef_extension_without_strict_mode(text)
        record = {}
        begin
          text.scan(EXTENSION_KEY_VALUE_SCANNER) do |extension_field_key, raw_extension_field_value|
             # expand abbreviated extension field keys
             extension_field_key = MAPPINGS.fetch(extension_field_key, extension_field_key)

             # convert extension field name to strict legal field_reference, fixing field names with ambiguous array-like syntax
             extension_field_key = extension_field_key.sub(EXTENSION_KEY_ARRAY_CAPTURE, '[\1]\2') if extension_field_key.end_with?(']')

             # process legal extension field value escapes
             extension_field_value = raw_extension_field_value.gsub(EXTENSION_VALUE_ESCAPE_CAPTURE, '\1')

             # event.set(extension_field_key, extension_field_value)
             record[extension_field_key] = extension_field_value.rstrip
          end
        rescue
          return {}
        end
        return record
      end
    end
  end
end

