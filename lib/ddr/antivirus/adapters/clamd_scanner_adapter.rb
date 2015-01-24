require_relative "scanner_adapter"
require_relative "scan_result"

module Ddr
  module Antivirus
    module Adapters
      #
      # Adapter for clamd client (clamdscan)
      #
      class ClamdScannerAdapter < ScannerAdapter

        def scan(path)
          raw = clamdscan(path)
          ClamdScanResult.new(raw, path)
        end

        def clamdscan(path)
          Open3.capture3("clamdscan --no-summary #{path}")
        end

      end

      #
      # Result of a scan with the ClamdScannerAdapter
      #
      class ClamdScanResult < ScanResult
        
        def virus_found
          if has_virus?
            m = /: ([^\s]+) FOUND$/.match(raw[0])
            m[1]
          end
        end

        def has_virus?
          raw[2].exitstatus == 1
        end

        def error?
          raw[2].exitstatus == 2
        end

        def error
          if error?
            m = /^ERROR: (.+)$/.match(raw[1])
            m[1]
          end
        end

        def ok?
          raw[2].exitstatus == 0
        end

        def to_s
          "#{raw[0]} (#{version})"
        end

        def default_version
          `sigtool --version`.strip
        end

      end

    end
  end
end
