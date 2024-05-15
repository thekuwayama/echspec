module EchSpec
  module Spec
    class Spec5_1_9
      # The client-facing server computes ClientHelloInner by reversing this
      # process. First it parses EncodedClientHelloInner, interpreting all
      # bytes after client_hello as padding. If any padding byte is non-
      # zero, the server MUST abort the connection with an
      # "illegal_parameter" alert.
      #
      # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-18#section-5.1-9

      # @return [EchSpec::SpecGroup]
      def self.spec_group
        SpecGroup.new(
          '5.1-9',
          [
            SpecCase.new(
              'MUST abort with an "illegal_parameter" alert, if EncodedClientHelloInner is padded with non-zero values.',
              method(:validate_nonzero_padding_encoded_ch_inner)
            )
          ]
        )
      end

      # @param hostname [String]
      # @param port [Integer]
      # @param ech_config [ECHConfig]
      #
      # @return [EchSpec::Ok | Err]
      def self.validate_nonzero_padding_encoded_ch_inner(hostname, port, ech_config)
        socket = TCPSocket.new(hostname, port)
        spec = Spec5_1_9.new
        recv = spec.send_nonzero_padding_encoded_ch_inner(socket, hostname, ech_config)
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

      def send_nonzero_padding_encoded_ch_inner(socket, hostname, ech_config)
        conn = TLS13Client::Connection.new(socket, :client)
        inner_ech = TTTLS13::Message::Extension::ECHClientHello.new_inner
        exs, = TLS13Client.gen_ch_extensions(hostname)
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
        ch, = NonzeroPaddingEch.offer_ech(inner, ech_config, selector)
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

      class NonzeroPaddingEch < TTTLS13::Ech
        NON_ZERO = "\x11".freeze

        # @param s [String]
        # @param server_name_length [Integer]
        # @param maximum_name_length [Integer]
        #
        # @return [String]
        def self.padding_encoded_ch_inner(s,
                                          server_name_length,
                                          maximum_name_length)
          padding_len =
            if server_name_length.positive?
              [maximum_name_length - server_name_length, 0].max
            else
              9 + maximum_name_length
            end

          padding_len = 31 - ((s.length + padding_len - 1) % 32)
          s + NON_ZERO * padding_len # padding with non-zero value
        end
      end
    end
  end
end
