module EchSpec
  module Spec
    class Spec7_1_14_2_1
      # Otherwise, if all candidate ECHConfig values fail to decrypt the
      # extension, the client-facing server MUST ignore the extension and
      # proceed with the connection using ClientHelloOuter, with the
      # following modifications:
      #
      # * If the server is configured with any ECHConfigs, it MUST include
      #   the "encrypted_client_hello" extension in its EncryptedExtensions
      #   with the "retry_configs" field set to one or more ECHConfig
      #   structures with up-to-date keys. Servers MAY supply multiple
      #   ECHConfig values of different versions. This allows a server to
      #   support multiple versions at once.
      #
      # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-22#section-7.1-14.2.1

      # @return [EchSpec::SpecGroup]
      def self.spec_group
        SpecGroup.new(
          '7.1-14.2.1',
          [
            SpecCase.new(
              'MUST include the "encrypted_client_hello" extension in its EncryptedExtensions with the "retry_configs" field set to one or more ECHConfig.',
              method(:validate_ee_retry_configs)
            )
          ]
        )
      end

      # @param hostname [String]
      # @param port [Integer]
      # @param _ [ECHConfig]
      #
      # @return [EchSpec::Ok | Err]
      def self.validate_ee_retry_configs(hostname, port, _)
        socket = TCPSocket.new(hostname, port)
        spec = Spec7_1_14_2_1.new
        recv = spec.send_ch_with_greased_ech(socket, hostname)
        socket.close
        ex = recv.extensions[TTTLS13::Message::ExtensionType::ENCRYPTED_CLIENT_HELLO]
        return Err.new('did not send expected alert: encrypted_client_hello', spec.message_stack) \
          unless ex.is_a?(TTTLS13::Message::Extension::ECHEncryptedExtensions)
        return Err.new('ECHConfigs did not have "retry_configs"', spec.message_stack) \
          if ex.retry_configs.nil? || ex.retry_configs.empty?

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

      # rubocop: disable Metrics/AbcSize
      # rubocop: disable Metrics/MethodLength
      def send_ch_with_greased_ech(socket, hostname)
        # send ClientHello
        conn = TLS13Client::Connection.new(socket, :client)
        inner_ech = TTTLS13::Message::Extension::ECHClientHello.new_inner
        exs, priv_keys = TLS13Client.gen_ch_extensions(hostname)
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

        ch, = TTTLS13::Ech.new_greased_ch(inner, TTTLS13::Ech.new_grease_ech)
        conn.send_record(
          TTTLS13::Message::Record.new(
            type: TTTLS13::Message::ContentType::HANDSHAKE,
            messages: [ch],
            cipher: TTTLS13::Cryptograph::Passer.new
          )
        )
        @stack << ch

        # receive ServerHello
        recv, = conn.recv_message(TTTLS13::Cryptograph::Passer.new)
        @stack << recv
        raise Error::BeforeTargetSituationError, 'not received ServerHello' \
          unless recv.is_a?(TTTLS13::Message::ServerHello) && !recv.hrr?

        # receive EncryptedExtensions
        transcript = TTTLS13::Transcript.new
        transcript[TTTLS13::CH] = [ch, ch.serialize]
        sh = recv
        transcript[TTTLS13::SH] = [sh, sh.serialize]
        kse = sh.extensions[TTTLS13::Message::ExtensionType::KEY_SHARE]
                .key_share_entry.first
        shared_secret = TTTLS13::Endpoint.gen_shared_secret(
          kse.key_exchange,
          priv_keys[kse.group],
          kse.group
        )
        key_schedule = TTTLS13::KeySchedule.new(
          psk: nil,
          shared_secret:,
          cipher_suite: sh.cipher_suite,
          transcript:
        )
        hs_rcipher = TTTLS13::Endpoint.gen_cipher(
          sh.cipher_suite,
          key_schedule.server_handshake_write_key,
          key_schedule.server_handshake_write_iv
        )
        recv, = conn.recv_message(hs_rcipher)
        @stack << recv
        if recv.is_a?(TTTLS13::Message::ChangeCipherSpec)
          recv, = conn.recv_message(hs_rcipher)
          @stack << recv
        end

        raise Error::BeforeTargetSituationError, 'not received EncryptedExtensions' \
          unless recv.is_a?(TTTLS13::Message::EncryptedExtensions)

        recv
      end
      # rubocop: enable Metrics/AbcSize
      # rubocop: enable Metrics/MethodLength
    end
  end
end
