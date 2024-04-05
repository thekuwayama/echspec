module EchSpec
  module Spec
    class Spec7_1_1_2
      # If the client-facing server accepted ECH, it checks the second
      # ClientHelloOuter also contains the "encrypted_client_hello"
      # extension. If not, it MUST abort the handshake with a
      # "missing_extension" alert. Otherwise, it checks that
      # ECHClientHello.cipher_suite and ECHClientHello.config_id are
      # unchanged, and that ECHClientHello.enc is empty. If not, it MUST
      # abort the handshake with an "illegal_parameter" alert.
      #
      # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-7.1.1-2

      # @return [EchSpec::SpecGroup]
      def self.spec_group
        SpecGroup.new(
          '7.1.1-2',
          [
            SpecCase.new(
              'MUST abort with a "missing_extension" alert, if 2nd ClientHelloOuter does not contains the "encrypted_client_hello" extension',
              method(:validate_2nd_ch_missing_ech)
            ),
            SpecCase.new(
              'MUST abort with an "illegal_parameter" alert, if 2nd ClientHelloOuter "encrypted_client_hello" enc is empty',
              method(:validate_2nd_ch_unchanged_ech)
            )
          ]
        )
      end

      # @param hostname [String]
      # @param port [Integer]
      # @param ech_config [ECHConfig]
      #
      # @return [EchSpec::Ok | Err]
      def self.validate_2nd_ch_missing_ech(hostname, port, ech_config)
        socket = TCPSocket.new(hostname, port)
        recv = send_2nd_ch_missing_ech(socket, hostname, ech_config)
        socket.close
        return Err.new('did not send expected alert: missing_extension') \
          unless Spec.expect_alert(recv, :missing_extension)

        Ok.new(nil)
      rescue Timeout::Error
        Err.new("#{hostname}:#{port} connection timeout")
      rescue Errno::ECONNREFUSED
        Err.new("#{hostname}:#{port} connection refused")
      rescue Error::BeforeTargetSituationError => e
        Err.new(e.message)
      end

      # @param hostname [String]
      # @param port [Integer]
      # @param ech_config [ECHConfig]
      #
      # @return [EchSpec::Ok | Err]
      def self.validate_2nd_ch_unchanged_ech(hostname, port, ech_config)
        socket = TCPSocket.new(hostname, port)
        recv = send_2nd_ch_unchanged_ech(socket, hostname, ech_config)
        socket.close
        return Err.new('did not send expected alert: illegal_parameter') \
          unless Spec.expect_alert(recv, :illegal_parameter)

        Ok.new(nil)
      rescue Timeout::Error
        Err.new("#{hostname}:#{port} connection timeout")
      rescue Errno::ECONNREFUSED
        Err.new("#{hostname}:#{port} connection refused")
      rescue Error::BeforeTargetSituationError => e
        Err.new(e.message)
      end

      def self.send_2nd_ch_missing_ech(socket, hostname, ech_config)
        conn, ch1, hrr, = TLS13Client.recv_hrr(socket, hostname, ech_config)
        # send 2nd ClientHello without ech
        new_exs = TLS13Client.gen_newch_extensions(ch1, hrr)
        new_exs.delete(TTTLS13::Message::ExtensionType::ENCRYPTED_CLIENT_HELLO)
        ch = TTTLS13::Message::ClientHello.new(
          legacy_version: ch1.legacy_version,
          random: ch1.random,
          legacy_session_id: ch1.legacy_session_id,
          cipher_suites: ch1.cipher_suites,
          legacy_compression_methods: ch1.legacy_compression_methods,
          extensions: new_exs
        )
        conn.send_record(
          TTTLS13::Message::Record.new(
            type: TTTLS13::Message::ContentType::HANDSHAKE,
            messages: [ch],
            cipher: TTTLS13::Cryptograph::Passer.new
          )
        )

        recv, = conn.recv_message(TTTLS13::Cryptograph::Passer.new)
        recv, = conn.recv_message(TTTLS13::Cryptograph::Passer.new) \
          if recv.is_a?(TTTLS13::Message::ChangeCipherSpec)
        recv
      end

      def self.send_2nd_ch_unchanged_ech(socket, hostname, ech_config)
        conn, ch1, hrr, = TLS13Client.recv_hrr(socket, hostname, ech_config)
        # send 2nd ClientHello with unchanged ech
        new_exs = TLS13Client.gen_newch_extensions(ch1, hrr)
        new_exs[TTTLS13::Message::ExtensionType::ENCRYPTED_CLIENT_HELLO] =
          ch1.extensions[TTTLS13::Message::ExtensionType::ENCRYPTED_CLIENT_HELLO]
        ch = TTTLS13::Message::ClientHello.new(
          legacy_version: ch1.legacy_version,
          random: ch1.random,
          legacy_session_id: ch1.legacy_session_id,
          cipher_suites: ch1.cipher_suites,
          legacy_compression_methods: ch1.legacy_compression_methods,
          extensions: new_exs
        )
        conn.send_record(
          TTTLS13::Message::Record.new(
            type: TTTLS13::Message::ContentType::HANDSHAKE,
            messages: [ch],
            cipher: TTTLS13::Cryptograph::Passer.new
          )
        )

        recv, = conn.recv_message(TTTLS13::Cryptograph::Passer.new)
        recv, = conn.recv_message(TTTLS13::Cryptograph::Passer.new) \
          if recv.is_a?(TTTLS13::Message::ChangeCipherSpec)
        recv
      end
    end
  end
end
