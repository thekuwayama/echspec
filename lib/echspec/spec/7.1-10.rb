module EchSpec
  module Spec
    class Spec7_1_10
      # Upon determining the ClientHelloInner, the client-facing server
      # checks that the message includes a well-formed
      # "encrypted_client_hello" extension of type inner and that it does not
      # offer TLS 1.2 or below. If either of these checks fails, the client-
      # facing server MUST abort with an "illegal_parameter" alert.
      #
      # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-7.1-10

      # @return [SpecGroup]
      def self.spec_group
        SpecGroup.new(
          '7.1-10',
          [
            SpecCase.new(
              'MUST abort with an "illegal_parameter" alert, if ClientHelloInner offers TLS 1.2 or below',
              method(:validate_ech_with_tls12)
            )
          ]
        )
      end

      # @param hostname [String]
      # @param port [Integer]
      # @param ech_config [ECHConfig]
      #
      # @return [EchSpec::Ok | Err]
      def self.validate_ech_with_tls12(hostname, port, ech_config)
        socket = TCPSocket.new(hostname, port)
        spec = Spec7_1_10.new
        recv = spec.send_ch_ech_with_tls12(socket, hostname, ech_config)
        socket.close
        return Err.new('did not send expected alert: illegal_parameter', spec.message_stack) \
          unless Spec.expect_alert(recv, :illegal_parameter)

        Ok.new(nil)
      rescue Timeout::Error
        Err.new("#{hostname}:#{port} connection timeout", spec.message_stack)
      rescue Errno::ECONNREFUSED
        Err.new("#{hostname}:#{port} connection refused", spec.message_stack)
      end

      def initialize
        @stack = Log::MessageStack.new
      end

      def message_stack
        @stack.marshal
      end

      # rubocop: disable Metrics/MethodLength
      def send_ch_ech_with_tls12(socket, hostname, ech_config)
        conn = TLS13Client::Connection.new(socket, :client)
        inner_ech = TTTLS13::Message::Extension::ECHClientHello.new_inner
        exs, = TLS13Client.gen_ch_extensions(hostname)
        # supported_versions: only TLS 1.2
        versions = TTTLS13::Message::Extension::SupportedVersions.new(
          msg_type: TTTLS13::Message::HandshakeType::CLIENT_HELLO,
          versions: [TTTLS13::Message::ProtocolVersion::TLS_1_2]
        )
        exs[TTTLS13::Message::ExtensionType::SUPPORTED_VERSIONS] = versions
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
        @stack.ch_inner(inner)

        selector = proc { |x| TLS13Client.select_ech_hpke_cipher_suite(x) }
        ch, = TTTLS13::Ech.offer_ech(inner, ech_config, selector)
        conn.send_record(
          TTTLS13::Message::Record.new(
            type: TTTLS13::Message::ContentType::HANDSHAKE,
            messages: [ch],
            cipher: TTTLS13::Cryptograph::Passer.new
          )
        )
        @stack << ch

        recv, = conn.recv_message(TTTLS13::Cryptograph::Passer.new)
        @stack << recv

        recv
      end
      # rubocop: enable Metrics/MethodLength
    end
  end
end
