module EchSpec
  module Spec
    class Spec7_2_1 < WithSocket
      # Upon receipt of an "encrypted_client_hello" extension of type inner
      # in a ClientHello, if the backend server negotiates TLS 1.3 or higher,
      # then it MUST confirm ECH acceptance to the client by computing its
      # ServerHello as described here.
      #
      # https://datatracker.ietf.org/doc/html/rfc9849#section-7.2-1

      # @return [EchSpec::SpecGroup]
      def self.spec_group
        SpecGroup.new(
          '7.2-1',
          [
            SpecCase.new(
              'MUST confirm ECH acceptance in ServerHello, if it confirmed ECH acceptance in HelloRetryRequest.',
              method(:validate_sh_confirmation_after_hrr)
            )
          ]
        )
      end

      # @param hostname [String]
      # @param port [Integer]
      # @param ech_config [ECHConfig]
      #
      # @return [EchSpec::Ok | Err]
      def self.validate_sh_confirmation_after_hrr(hostname, port, ech_config)
        Spec7_2_1.new.do_validate_sh_confirmation_after_hrr(hostname, port, ech_config)
      end

      # @param hostname [String]
      # @param port [Integer]
      # @param ech_config [ECHConfig]
      #
      # @return [EchSpec::Ok | Err]
      def do_validate_sh_confirmation_after_hrr(hostname, port, ech_config)
        with_socket(hostname, port) do |socket|
          recv, confirmation = send_2nd_ch_after_hrr(socket, hostname, ech_config)
          return Err.new('did not send expected handshake message: ServerHello', message_stack) \
            unless recv.is_a?(TTTLS13::Message::ServerHello) && !recv.hrr?

          validate_sh_confirmation(confirmation, recv)
        end
      end

      # @param expected [String] accept_confirmation
      # @param sh [TTTLS13::Message::ServerHello]
      #
      # @return [EchSpec::Ok | Err]
      def validate_sh_confirmation(expected, sh)
        return Ok.new(nil) if sh.random[-8..] == expected

        Err.new('the last 8 bytes of ServerHello.random did not match accept_confirmation, although HelloRetryRequest confirmed ECH acceptance', message_stack)
      end

      # rubocop: disable Metrics/AbcSize
      # rubocop: disable Metrics/MethodLength
      def send_2nd_ch_after_hrr(socket, hostname, ech_config)
        conn, inner1, _ch1, hrr, ech_state = TLS13Client.recv_hrr(socket, hostname, ech_config, @stack)
        transcript = TTTLS13::Transcript.new
        transcript[TTTLS13::CH1] = [inner1, inner1.serialize]
        transcript[TTTLS13::HRR] = [hrr, hrr.serialize]
        # shared_secret is not used to compute (hrr_)accept_confirmation
        key_schedule = TTTLS13::KeySchedule.new(
          shared_secret: nil,
          cipher_suite: hrr.cipher_suite,
          transcript:
        )
        ex = hrr.extensions[TTTLS13::Message::ExtensionType::ENCRYPTED_CLIENT_HELLO]
        raise Error::BeforeTargetSituationError, 'HelloRetryRequest did not confirm ECH acceptance' \
          if ex.nil? || ex.confirmation != key_schedule.hrr_accept_confirmation

        # send 2nd ClientHello; ClientHelloInner2 is based on ClientHelloInner1,
        # and its "encrypted_client_hello" extension of type inner is left
        # unmodified.
        inner2 = TTTLS13::Message::ClientHello.new(
          legacy_version: inner1.legacy_version,
          random: inner1.random,
          legacy_session_id: inner1.legacy_session_id,
          cipher_suites: inner1.cipher_suites,
          legacy_compression_methods: inner1.legacy_compression_methods,
          extensions: TLS13Client.gen_newch_extensions(inner1, hrr)
        )
        ch, inner2 = TTTLS13::Ech.offer_new_ech(inner2, ech_state)
        conn.send_record(
          TTTLS13::Message::Record.new(
            type: TTTLS13::Message::ContentType::HANDSHAKE,
            messages: [ch],
            cipher: TTTLS13::Cryptograph::Passer.new
          )
        )
        @stack << inner2
        @stack << ch

        recv, = conn.recv_message(TTTLS13::Cryptograph::Passer.new)
        recv, = conn.recv_message(TTTLS13::Cryptograph::Passer.new) \
          if recv.is_a?(TTTLS13::Message::ChangeCipherSpec)
        @stack << recv
        return [recv, nil] unless recv.is_a?(TTTLS13::Message::ServerHello) && !recv.hrr?

        transcript[TTTLS13::CH] = [inner2, inner2.serialize]
        sh = recv
        transcript[TTTLS13::SH] = [sh, sh.serialize]
        [recv, key_schedule.accept_confirmation]
      end
      # rubocop: enable Metrics/AbcSize
      # rubocop: enable Metrics/MethodLength
    end
  end
end
