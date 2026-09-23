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
          conn, inner1, hrr, hrr_bin, ech_state = recv_hrr_accepting_ech(socket, hostname, ech_config)
          inner2 = send_2nd_ch(conn, inner1, hrr, ech_state)

          recv, orig_msg = conn.recv_message(TTTLS13::Cryptograph::Passer.new)
          @stack << recv
          if recv.is_a?(TTTLS13::Message::ChangeCipherSpec)
            recv, orig_msg = conn.recv_message(TTTLS13::Cryptograph::Passer.new)
            @stack << recv
          end
          return Err.new('did not send expected handshake message: ServerHello', message_stack) \
            unless recv.is_a?(TTTLS13::Message::ServerHello) && !recv.hrr?

          expected = TLS13Client.accept_confirmation(inner1, hrr, hrr_bin, inner2, recv, orig_msg)
          validate_sh_confirmation(expected, recv)
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

      private

      # @param socket [TCPSocket]
      # @param hostname [String]
      # @param ech_config [ECHConfig]
      #
      # @raise [EchSpec::Error::BeforeTargetSituationError]
      #
      # @return [EchSpec::TLS13Client::Connection]
      # @return [TTTLS13::Message::ClientHello] ClientHelloInner1
      # @return [TTTLS13::Message::ServerHello] HelloRetryRequest
      # @return [String] HelloRetryRequest as received
      # @return [TTTLS13::EchState]
      def recv_hrr_accepting_ech(socket, hostname, ech_config)
        conn, inner1, _ch1, hrr, ech_state, hrr_bin = TLS13Client.recv_hrr(socket, hostname, ech_config, @stack)
        # Extensions#[] returns nil for UnknownExtension, so use super_fetch.
        ex = hrr.extensions.super_fetch(TTTLS13::Message::ExtensionType::ENCRYPTED_CLIENT_HELLO, nil)
        raise Error::BeforeTargetSituationError, 'HelloRetryRequest did not confirm ECH acceptance' \
          unless ex.is_a?(TTTLS13::Message::Extension::ECHHelloRetryRequest) &&
                 ex.confirmation == TLS13Client.hrr_accept_confirmation(inner1, hrr, hrr_bin)

        [conn, inner1, hrr, hrr_bin, ech_state]
      end

      # @param conn [EchSpec::TLS13Client::Connection]
      # @param inner1 [TTTLS13::Message::ClientHello] ClientHelloInner1
      # @param hrr [TTTLS13::Message::ServerHello] HelloRetryRequest
      # @param ech_state [TTTLS13::EchState]
      #
      # @return [TTTLS13::Message::ClientHello] ClientHelloInner2
      def send_2nd_ch(conn, inner1, hrr, ech_state)
        # ClientHelloInner2 is based on ClientHelloInner1, and its
        # "encrypted_client_hello" extension of type inner is left unmodified.
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

        inner2
      end
    end
  end
end
