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
        in Ok
          puts "\t#{desc.green}"
        in Err
          puts "\t#{desc.red}"
        end
      end

      # @param result [EchSpec::Err]
      # @param idx [Integer]
      # @param desc [String]
      # @param verbose [Boolean]
      def print_err_details(err, idx, desc, verbose)
        puts "\t(#{idx + 1}) #{desc}"
        details =  "\t\t#{err.details}"
        details += ", messge stack: #{err.message_stack}" if verbose && !err.message_stack.nil?
        puts details
      end
    end
  end
end

Dir["#{File.dirname(__FILE__)}/spec/*.rb"].sort.each { |f| require f }

module EchSpec
  module Spec
    class << self
      # @param fpath [String]
      # @param port [Integer]
      # @param hostname [String]
      # @param force_compliant [Boolean]
      # @param verbose [Boolean]
      # rubocop: disable Metrics/AbcSize
      # rubocop: disable Metrics/CyclomaticComplexity
      def run(fpath, port, hostname, force_compliant, verbose)
        TTTLS13::Logging.logger.level = Logger::WARN
        ech_config = try_get_ech_config(fpath, hostname, force_compliant)

        results = spec_groups.flat_map do |g|
          g.spec_cases.map do |sc|
            d = "#{sc.description} [#{g.section}]"
            r = sc.method.call(hostname, port, ech_config)
            { result: r, desc: d }
          end
        end
        results.each { |h| print_summarize(h[:result], h[:desc]) }
        return if results.all? { |h| h[:result].is_a? Ok }

        puts 'Failures:'
        results.filter { |h| h[:result].is_a? Err }
               .each
               .with_index { |h, idx| print_err_details(h[:result], idx, h[:desc], verbose) }
      end
      # rubocop: enable Metrics/AbcSize
      # rubocop: enable Metrics/CyclomaticComplexity

      def try_get_ech_config(fpath, hostname, force_compliant)
        # 9
        case result = Spec9.try_get_ech_config(fpath, hostname, force_compliant)
        in Ok(obj)
          result.tap { |r| print_summarize(r, Spec9.description) }
          obj
        in Err(details, _)
          puts "\t\t#{details}"
          exit 1
        end
      end

      def spec_groups
        # 5
        groups = [Spec5_1_9, Spec5_1_10]

        # 7
        groups += [Spec7_2_3_1, Spec7_1_10, Spec7_1_13_2_1, Spec7_1_1_2, Spec7_1_1_5]

        groups.map(&:spec_group)
      end
    end
  end
end
