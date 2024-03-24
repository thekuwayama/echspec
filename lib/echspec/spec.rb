module EchSpec
  module Spec
    class << self
      using Refinements

      # @param record [TTTLS13::Message::Record]
      # @param desc [Symbol]
      #
      # @return [Boolean]
      def expect_alert(msg, desc)
        msg.is_a?(TTTLS13::Message::Alert) &&
          msg.description == TTTLS13::Message::ALERT_DESCRIPTION[desc]
      end

      # @param result [EchSpec::Ok | Err]
      # @param desc [String]
      def print_summarize(result, desc)
        case result
        in Ok(_)
          puts "\t#{desc.green}"
        in Err(_)
          puts "\t#{desc.red}"
        end
      end

      # @param result [EchSpec::Ok | Err]
      # @param idx [Integer]
      # @param desc [String]
      def print_failed_details(result, idx, desc)
        case result
        in Ok(_)
          return
        in Err(details)
          puts "\t(#{idx + 1}) #{desc}"
          puts "\t\t#{details}"
        end
      end
    end
  end
end

Dir[File.dirname(__FILE__) + '/spec/*.rb'].sort.each { |f| require f }

module EchSpec
  module Spec
    class << self
      # @param fpath [String]
      # @param port [Integer]
      # @param hostname [String]
      # @param force_compliant [Boolean]
      def run(fpath, port, hostname, force_compliant)
        TTTLS13::Logging.logger.level = Logger::WARN

        # 9
        case Spec9.try_get_ech_config(fpath, hostname, force_compliant)
        in Ok(obj)
          ech_config = obj
        in Err(details)
          puts "\t\t#{details}"
          return
        end

        # 7
        specs = [Spec7_2_3_1, Spec7_1_1_2, Spec7_1_10, Spec7_1_13_2_1]
        results = specs.flat_map do |spec|
          desc = spec.description
          spec.run(hostname, port, ech_config).map do |r|
            { result: r, desc: desc }
          end
        end

        results.each { |h| print_summarize(h[:result], h[:desc]) }
        return if results.all? { |h| h[:result].is_a? Ok }

        puts 'Failures:'
        results.each.with_index { |h, idx| print_failed_details(h[:result], idx, h[:desc]) }
      end
    end
  end
end
