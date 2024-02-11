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
      def print_summarize(result)
        case result
        in Ok(description)
          puts "\t#{description.green}"
        in Err(description, _)
          puts "\t#{description.red}"
        end
      end

      # @param result [EchSpec::Ok | Err]
      # @param idx [Integer]
      def print_failed_details(result, idx)
        case result
        in Ok(_)
        in Err(description, details)
          puts "\t(#{idx + 1}) #{description}"
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
      def run(fpath, port, hostname)
        TTTLS13::Logging.logger.level = Logger::WARN

        # 9
        echconfigs = if fpath.nil?
                       Spec9.resolve_echconfigs(hostname)
                     else
                       Spec9.parse_pem(File.open(fpath).read)
                     end
        Spec9.validate_compliant_echconfigs(echconfigs).tap { |x| print_summarize(x) }
        ech_config = echconfigs.first

        # 7
        results = [Spec7_2_3_1, Spec7_1_1_2, Spec7_1_10, Spec7_1_13_2_1]
                  .flat_map { |spec| spec.run(hostname, port, ech_config) }
        results.each { |x| print_summarize(x) }

        return if results.all? { |r| r.is_a? Ok }

        puts 'Failures:'
        results.each.with_index { |r, idx| print_failed_details(r, idx) }
      end
    end
  end
end
