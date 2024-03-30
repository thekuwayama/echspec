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

      # @param socket [TCPSocket]
      # @param hostname [String]
      # @param ech_config [ECHConfig]
      #
      # @raise [EchSpec::Error::BeforeTargetSituationError]
      #
      # @return [EchSpec::TLS13Client::Connection]
      # @return [TTTLS13::Message::ClientHello]
      # @return [TTTLS13::Message::ServerHello] HelloRetryRequest
      def recv_hrr(socket, hostname, ech_config)
        # send 1st ClientHello
        conn = TLS13Client::Connection.new(socket, :client)
        inner_ech = TTTLS13::Message::Extension::ECHClientHello.new_inner
        exs, = TLS13Client.gen_ch_extensions(hostname)
        exs.delete(TTTLS13::Message::ExtensionType::KEY_SHARE) # for HRR
        inner = TTTLS13::Message::ClientHello.new(
          cipher_suites: TTTLS13::CipherSuites.new(
            [
              TTTLS13::CipherSuite::TLS_AES_256_GCM_SHA384,
              TTTLS13::CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
              TTTLS13::CipherSuite::TLS_AES_128_GCM_SHA256
            ]
          ),
          extensions: exs.merge(
            TTTLS13::Message::ExtensionType::ENCRYPTED_CLIENT_HELLO => inner_ech
          )
        )

        selector = proc { |x| TLS13Client.select_ech_hpke_cipher_suite(x) }
        ch, = TTTLS13::Ech.offer_ech(inner, ech_config, selector)
        conn.send_record(
          TTTLS13::Message::Record.new(
            type: TTTLS13::Message::ContentType::HANDSHAKE,
            messages: [ch],
            cipher: TTTLS13::Cryptograph::Passer.new
          )
        )

        # receive HelloRetryRequest
        recv, = conn.recv_message(TTTLS13::Cryptograph::Passer.new)
        raise Error::BeforeTargetSituationError, 'not received HelloRetryRequest' \
          unless recv.hrr?

        [conn, ch, recv]
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
        case result = Spec9.try_get_ech_config(fpath, hostname, force_compliant)
        in Ok(obj)
          result.tap { |r| print_summarize(r, Spec9.description) }
          ech_config = obj
        in Err(details)
          puts "\t\t#{details}"
          return
        end

        # 7
        groups = [Spec7_2_3_1, Spec7_1_10, Spec7_1_13_2_1, Spec7_1_1_2].map(&:spec_group)
        results = groups.flat_map do |g|
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
               .with_index { |h, idx| print_failed_details(h[:result], idx, h[:desc]) }
      end
    end
  end
end
