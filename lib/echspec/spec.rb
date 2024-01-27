module EchSpec
  module Spec
    class << self
      # @param record [TTTLS13::Message::Record]
      # @param desc [Symbol]
      #
      # @return [Boolean]
      def expect_alert(record, desc)
        description = TTTLS13::Message::ALERT_DESCRIPTION[desc]

        record.type == TTTLS13::Message::ContentType::ALERT &&
          record.messages.first.description == description
      end
    end
  end
end

Dir[File.dirname(__FILE__) + '/spec/*.rb'].sort.each { |f| require f }

module EchSpec
  module Spec
    class << self
      using Refinements

      # @param result [EchSpec::Ok or Err]
      def print_result(result)
        case result
        in Ok(message)
          puts message.green
        in Err(message)
          puts message.red
        end
      end

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

        # 7-2.3.1
        Spec7_2_3_1.validate_illegal_ech_type(hostname, port, echconfigs.first).each { |x| print_result(x) }
      end
    end
  end
end
