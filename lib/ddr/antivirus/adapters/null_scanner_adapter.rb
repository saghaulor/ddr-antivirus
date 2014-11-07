module Ddr
  module Antivirus
    module Adapters
      #
      # The NullScannerAdapter provides a no-op adapter, primarily for testing and development.
      #
      class NullScannerAdapter < ScannerAdapter

        class NullScanResult < Ddr::Antivirus::ScanResult; end

        def scan(path)
          NullScanResult.new("#{path}: NOT SCANNED - using :null scanner adapter.", path)
        end

      end
    end
  end
end
