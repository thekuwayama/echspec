module EchSpec
  module Spec
    class << self
      # @param record [TTTLS13::Message::Record]
      # @param id [Symbol]
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

      def run(fpath, port, hostname)
        TTTLS13::Logging.logger.level = Logger::WARN

        # 9
        if fpath.nil?
          echconfigs = Spec9.resolve_echconfigs(hostname)
        else
          echconfigs = Spec9.parse_pem(File.open(fpath).read)
        end

        case Spec9.validate_compliant_echconfigs(echconfigs)
        in Ok(message)
          puts message.green
        in Err(message)
          puts message.red
        end

        # 7-2.3.1
        case Spec7_2_3_1.run(hostname, port, echconfigs.first)
        in Ok(message)
          puts message.green
        in Err(message)
          puts message.red
        end
      end
    end
  end
end
