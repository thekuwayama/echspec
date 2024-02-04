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
      def print_result(result)
        case result
        in Ok(message)
          puts message.green
        in Err(message)
          puts message.red
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
        Spec9.validate_compliant_echconfigs(echconfigs).tap { |x| print_result(x) }
        ech_config = echconfigs.first

        # 7-2.3.1
        Spec7_2_3_1.validate_illegal_ech_type(hostname, port, ech_config).each { |x| print_result(x) }

        # 7.1.1-2
        Spec7_1_1_2.validate_hrr_missing_ech(hostname, port, ech_config).tap { |x| print_result(x) }

        # 7.1-10
        Spec7_1_10.validate_ech_with_tls12(hostname, port, ech_config).tap { |x| print_result(x) }

        # 7.1-13.2.1
        Spec7_1_13_2_1.valid_ee_retry_configs(hostname, port).tap { |x| print_result(x) }
      end
    end
  end
end
