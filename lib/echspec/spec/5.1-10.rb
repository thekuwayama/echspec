module EchSpec
  module Spec
    class Spec5_1_10
      # Next it makes a copy of the client_hello field and copies the
      # legacy_session_id field from ClientHelloOuter. It then looks for an
      # "ech_outer_extensions" extension. If found, it replaces the extension
      # with the corresponding sequence of extensions in the
      # ClientHelloOuter. The server MUST abort the connection with an
      # "illegal_parameter" alert if any of the following are true:
      #
      # * Any referenced extension is missing in ClientHelloOuter.
      # * Any extension is referenced in OuterExtensions more than once.
      # * "encrypted_client_hello" is referenced in OuterExtensions.
      # * The extensions in ClientHelloOuter corresponding to those in
      #   OuterExtensions do not occur in the same order.
      #
      # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-5.1-10

      # @return [EchSpec::SpecGroup]
      def self.spec_group
        SpecGroup.new(
          '5.1-10',
          [
            SpecCase.new(
              'MUST abort with an "illegal_parameter" alert, if any referenced extension is missing in ClientHelloOuter.',
              method(:validate_missing_extension_ch_outer)
            )
          ]
        )
      end

      # @param hostname [String]
      # @param port [Integer]
      # @param ech_config [ECHConfig]
      #
      # @return [EchSpec::Ok | Err]
      def self.validate_missing_extension_ch_outer(hostname, port, ech_config)
        socket = TCPSocket.new(hostname, port)
        spec = Spec5_1_10.new
        recv = spec.send_missing_extension_ch_outer(socket, hostname, ech_config)
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

      def send_missing_extension_ch_outer(socket, hostname, ech_config)
        conn = TLS13Client::Connection.new(socket, :client)
        inner_ech = TTTLS13::Message::Extension::ECHClientHello.new_inner
        exs, = TLS13Client.gen_ch_extensions(hostname)
        exs = MissingReferencedExtensions.new(exs.values)
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

      class MissingReferencedExtensions < TTTLS13::Message::Extensions
        # @param outer_extensions [Array of TTTLS13::Message::ExtensionType]
        #
        # @return [TTTLS13::Message::Extensions] for EncodedClientHelloInner
        def remove_and_replace!(_)
          outer_extensions = [TTTLS13::Message::ExtensionType::KEY_SHARE]
          tmp1 = filter { |k, _| !outer_extensions.include?(k) }
          tmp2 = filter { |k, _| outer_extensions.include?(k) }

          clear
          replaced = TTTLS13::Message::Extensions.new

          tmp1.each_value { |v| self << v; replaced << v }
          # key_share is referenced, but it is missing in ClientHelloOuter.
          replaced << TTTLS13::Message::Extension::ECHOuterExtensions.new(tmp2.keys) \
            unless tmp2.keys.empty?

          replaced
        end
      end
    end
  end
end
