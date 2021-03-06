module Ddr
  module Antivirus
    module Adapters
      #
      # @abstract Subclass and override {#scan} to implement a scanner adapter.
      #
      class ScannerAdapter

        # Scan a file path for viruses.
        #
        # @param path [String] file path to scan.
        # @return [Ddr::Antivirus::Adapters::ScanResult] the result of the scan.
        def scan(path)
          raise NotImplementedError, "Adapters must implement the `scan' method."
        end

        # Return the adapter configuration options
        def config
          Ddr::Antivirus.adapter_config
        end

      end
    end
  end
end
