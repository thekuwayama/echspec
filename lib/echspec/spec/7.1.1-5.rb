module EchSpec
  module Spec
    class Spec7_1_1_5
      # ClientHelloOuterAAD is computed as described in Section 5.2, but
      # using the second ClientHelloOuter. If decryption fails, the client-
      # facing server MUST abort the handshake with a "decrypt_error" alert.
      # Otherwise, it reconstructs the second ClientHelloInner from the new
      # EncodedClientHelloInner as described in Section 5.1, using the
      # second ClientHelloOuter for any referenced extensions.
      #
      # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-22#section-7.1.1-5

      # @return [EchSpec::SpecGroup]
      def self.spec_group
        SpecGroup.new(
          '7.1.1-5',
          [
            SpecCase.new(
              'MUST abort with a "decrypt_error" alert, if fails to decrypt 2nd ClientHelloOuter.',
              method(:validate_undecryptable_2nd_ch_outer)
            )
          ]
        )
      end

      # @param hostname [String]
      # @param port [Integer]
      # @param ech_config [ECHConfig]
      #
      # @return [EchSpec::Ok | Err]
      def self.validate_undecryptable_2nd_ch_outer(hostname, port, ech_config)
        socket = TCPSocket.new(hostname, port)
        spec = Spec7_1_1_5.new
        recv = spec.send_2nd_ch_with_undecryptable_ech(socket, hostname, ech_config)
        socket.close
        return Err.new('did not send expected alert: decrypt_error', spec.message_stack) \
          unless Spec.expect_alert(recv, :decrypt_error)

        Ok.new(nil)
      rescue Timeout::Error
        Err.new("#{hostname}:#{port} connection timeout", spec.message_stack)
      rescue Errno::ECONNREFUSED
        Err.new("#{hostname}:#{port} connection refused", spec.message_stack)
      rescue Error::BeforeTargetSituationError => e
        Err.new(e.message, spec.message_stack)
      end

      def initialize
        @stack = Log::MessageStack.new
      end

      def message_stack
        @stack.marshal
      end

      def send_2nd_ch_with_undecryptable_ech(socket, hostname, ech_config)
        conn, ch1, hrr, ech_state = TLS13Client.recv_hrr(socket, hostname, ech_config, @stack)
        # send 2nd ClientHello with undecryptable ech
        new_exs = TLS13Client.gen_newch_extensions(ch1, hrr)
        ch = TTTLS13::Message::ClientHello.new(
          legacy_version: ch1.legacy_version,
          random: ch1.random,
          legacy_session_id: ch1.legacy_session_id,
          cipher_suites: ch1.cipher_suites,
          legacy_compression_methods: ch1.legacy_compression_methods,
          extensions: new_exs
        )
        ech_state.ctx.increment_seq # invalidly increment of the sequence number
        ch, = TTTLS13::Ech.offer_new_ech(ch, ech_state)
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

        recv, = conn.recv_message(TTTLS13::Cryptograph::Passer.new) \
          if recv.is_a?(TTTLS13::Message::ChangeCipherSpec)
        recv
      end
    end
  end
end
