module EchSpec
  module Spec
    class << self
      using Refinements

      # @param msg [TTTLS13::Message::Record]
      # @param desc [Symbol]
      #
      # @return [Boolean]
      def expect_alert(msg, desc)
        msg.is_a?(TTTLS13::Message::Alert) &&
          msg.description == TTTLS13::Message::ALERT_DESCRIPTION[desc]
      end

      ResultDesc = Struct.new(:result, :desc)

      # @param rds [Array<ResultDesc>] result: EchSpec::Ok | Err, desc: String
      # @param verbose [Boolean]
      def print_results(rds, verbose)
        rds.each { |rd| print_summary(rd.result, rd.desc) }
        failures = rds.filter { |rd| rd.result.is_a? Err }
        return if failures.empty?

        puts
        puts 'Failures:'
        puts
        failures.each
                .with_index { |rd, idx| print_err_details(rd.result, idx, rd.desc, verbose) }
        puts "#{failures.length} failure".red
      end

      # @param result [EchSpec::Ok | Err]
      # @param desc [String]
      def print_summary(result, desc)
        check = "\u2714"
        cross = "\u0078"
        summary = case result
                  in Ok
                    "#{check} #{desc}".green.indent
                  in Err
                    "#{cross} #{desc}".red.indent
                  end
        puts summary
      end

      # @param err [EchSpec::Err]
      # @param idx [Integer]
      # @param desc [String]
      # @param verbose [Boolean]
      def print_err_details(err, idx, desc, verbose)
        puts "#{idx + 1}) #{desc}".indent
        puts err.details.indent.indent
        warn err.message_stack if verbose && !err.message_stack.nil?
        puts
      end
    end

    class WithSocket
      def with_socket(hostname, port)
        socket = TCPSocket.new(hostname, port)
        yield(socket)
      rescue Timeout::Error
        Err.new("#{hostname}:#{port} connection timeout", message_stack)
      rescue Errno::ECONNREFUSED
        Err.new("#{hostname}:#{port} connection refused", message_stack)
      rescue Error::BeforeTargetSituationError => e
        Err.new(e.message, message_stack)
      ensure
        socket&.close
      end

      def initialize
        @stack = Log::MessageStack.new
      end

      def message_stack
        @stack.marshal
      end
    end
  end
end

Dir["#{File.dirname(__FILE__)}/spec/*.rb"].sort.each { |f| require f }

module EchSpec
  module Spec
    class << self
      using Refinements

      # @param fpath [String | NilClass]
      # @param port [Integer]
      # @param hostname [String]
      # @param force_compliant [Boolean]
      # @param verbose [Boolean]
      def run(fpath, port, hostname, force_compliant, verbose)
        TTTLS13::Logging.logger.level = Logger::WARN
        puts 'TLS Encrypted Client Hello Server'
        ech_config = try_get_ech_config(fpath, hostname, force_compliant)

        do_run(port, hostname, ech_config, spec_groups, verbose)
      end

      # @param fpath [String | NilClass]
      # @param port [Integer]
      # @param hostname [String]
      # @param sections [Array<String>]
      # @param verbose [Boolean]
      def run_only(fpath, port, hostname, sections, verbose)
        targets = spec_groups.filter { |g| sections.include?(g.section) }
        force_compliant = sections.include?(Spec9.section)

        TTTLS13::Logging.logger.level = Logger::WARN
        puts 'TLS Encrypted Client Hello Server'
        ech_config = try_get_ech_config(fpath, hostname, force_compliant)

        do_run(port, hostname, ech_config, targets, verbose)
      end

      # @param port [Integer]
      # @param hostname [String]
      # @param ech_config [ECHConfig]
      # @param targets [Array<EchSpec::SpecGroup>]
      # @param verbose [Boolean]
      def do_run(port, hostname, ech_config, targets, verbose)
        rds = targets.flat_map do |g|
          g.spec_cases.map do |sc|
            r = sc.method.call(hostname, port, ech_config)
            d = "#{sc.description} [#{g.section}]"
            ResultDesc.new(result: r, desc: d)
          end
        end

        print_results(rds, verbose)
      end

      # @param fpath [String | NilClass]
      # @param hostname [String]
      # @param force_compliant [Boolean]
      #
      # @return [ECHConfig]
      def try_get_ech_config(fpath, hostname, force_compliant)
        # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-22#section-9
        case result = Spec9.try_get_ech_config(fpath, hostname, force_compliant)
        in Ok(obj) if force_compliant
          result.tap { |r| print_summary(r, "#{Spec9.description} [#{Spec9.section}]") }
          obj
        in Ok(obj)
          obj
        in Err(details, _)
          puts details.red.indent
          exit 1
        end
      end

      def spec_groups
        # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-22#section-5
        groups = [Spec5_1_9, Spec5_1_10]

        # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-22#section-7
        groups += [Spec7_5, Spec7_1_11, Spec7_1_14_2_1, Spec7_1_1_2, Spec7_1_1_5]

        groups.map(&:spec_group)
      end

      def sections
        (spec_groups + [Spec9]).map(&:section)
      end
    end
  end
end
