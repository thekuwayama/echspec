module EchSpec
  module Spec
    class Spec7_5 < WithSocket
      # If ECHClientHello.type is not a valid ECHClientHelloType, then the
      # server MUST abort with an "illegal_parameter" alert.
      #
      # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-22#section-7-5

      # @return [EchSpec::SpecGroup]
      def self.spec_group
        SpecGroup.new(
          '7-5',
          [
            SpecCase.new(
              'MUST abort with an "illegal_parameter" alert, if ECHClientHello.type is not a valid ECHClientHelloType in ClientHelloInner.',
              method(:validate_illegal_inner_ech_type)
            ),
            SpecCase.new(
              'MUST abort with an "illegal_parameter" alert, if ECHClientHello.type is not a valid ECHClientHelloType in ClientHelloOuter.',
              method(:validate_illegal_outer_ech_type)
            )
          ]
        )
      end

      # @param hostname [String]
      # @param port [Integer]
      # @param ech_config [ECHConfig]
      #
      # @return [EchSpec::Ok | Err]
      def self.validate_illegal_inner_ech_type(hostname, port, ech_config)
        Spec7_5.new.do_validate_illegal_ech_type(
          hostname,
          port,
          ech_config,
          :send_ch_illegal_inner_ech_type
        )
      end

      # @param hostname [String]
      # @param port [Integer]
      # @param ech_config [ECHConfig]
      #
      # @return [EchSpec::Ok | Err]
      def self.validate_illegal_outer_ech_type(hostname, port, ech_config)
        Spec7_5.new.do_validate_illegal_ech_type(
          hostname,
          port,
          ech_config,
          :send_ch_illegal_outer_ech_type
        )
      end

      # @param hostname [String]
      # @param port [Integer]
      # @param ech_config [ECHConfig]
      # @param method [Method]
      #
      # @return [EchSpec::Ok | Err]
      def do_validate_illegal_ech_type(hostname, port, ech_config, method)
        with_socket(hostname, port) do |socket|
          recv = send(method, socket, hostname, ech_config)
          return Err.new('did not send expected alert: illegal_parameter', message_stack) \
            unless Spec.expect_alert(recv, :illegal_parameter)

          Ok.new(nil)
        end
      end

      # @param socket [TCPSocket]
      # @param hostname [String]
      # @param ech_config [ECHConfig]
      #
      # @return [TTTLS13::Message::Record]
      def send_ch_illegal_inner_ech_type(socket, hostname, ech_config)
        conn = TLS13Client::Connection.new(socket, :client)
        inner_ech = IllegalEchClientHello.new_inner
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
        @stack << inner

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

      # @param socket [TCPSocket]
      # @param hostname [String]
      # @param ech_config [ECHConfig]
      #
      # @return [TTTLS13::Message::Record]
      # rubocop: disable Metrics/AbcSize
      # rubocop: disable Metrics/MethodLength
      def send_ch_illegal_outer_ech_type(socket, hostname, ech_config)
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
        @stack << inner

        # offer_ech
        selector = proc { |x| TLS13Client.select_ech_hpke_cipher_suite(x) }

        # for ech_outer_extensions
        replaced = \
          inner.extensions.remove_and_replace!([])

        # Encrypted ClientHello Configuration
        ech_state, enc = TTTLS13::Ech.encrypted_ech_config(
          ech_config,
          selector
        )
        encoded = TTTLS13::Ech.encode_ch_inner(inner, ech_state.maximum_name_length, replaced)
        overhead_len = TTTLS13::Ech.aead_id2overhead_len(
          ech_state.cipher_suite.aead_id.uint16
        )

        # Encoding the ClientHelloInner
        aad_ech = IllegalEchClientHello.new_outer(
          cipher_suite: ech_state.cipher_suite,
          config_id: ech_state.config_id,
          enc:,
          payload: '0' * (encoded.length + overhead_len)
        )
        aad = TTTLS13::Message::ClientHello.new(
          legacy_version: inner.legacy_version,
          legacy_session_id: inner.legacy_session_id,
          cipher_suites: inner.cipher_suites,
          legacy_compression_methods: inner.legacy_compression_methods,
          extensions: inner.extensions.merge(
            TTTLS13::Message::ExtensionType::ENCRYPTED_CLIENT_HELLO => aad_ech,
            TTTLS13::Message::ExtensionType::SERVER_NAME => \
            TTTLS13::Message::Extension::ServerName.new(ech_state.public_name)
          )
        )

        # Authenticating the ClientHelloOuter
        # which does not include the Handshake structure's four byte header.
        outer_ech = IllegalEchClientHello.new_outer(
          cipher_suite: ech_state.cipher_suite,
          config_id: ech_state.config_id,
          enc:,
          payload: ech_state.ctx.seal(aad.serialize[4..], encoded)
        )
        outer = TTTLS13::Message::ClientHello.new(
          legacy_version: aad.legacy_version,
          random: aad.random,
          legacy_session_id: aad.legacy_session_id,
          cipher_suites: aad.cipher_suites,
          legacy_compression_methods: aad.legacy_compression_methods,
          extensions: aad.extensions.merge(
            TTTLS13::Message::ExtensionType::ENCRYPTED_CLIENT_HELLO => outer_ech
          )
        )
        conn.send_record(
          TTTLS13::Message::Record.new(
            type: TTTLS13::Message::ContentType::HANDSHAKE,
            messages: [outer],
            cipher: TTTLS13::Cryptograph::Passer.new
          )
        )
        @stack << outer

        recv, = conn.recv_message(TTTLS13::Cryptograph::Passer.new)
        @stack << recv

        recv
      end
      # rubocop: enable Metrics/AbcSize
      # rubocop: enable Metrics/MethodLength

      class IllegalEchClientHello < TTTLS13::Message::Extension::ECHClientHello
        using TTTLS13::Refinements

        ILLEGAL_OUTER = "\x02".freeze
        ILLEGAL_INNER = "\x03".freeze

        def self.new_inner
          IllegalEchClientHello.new(type: ILLEGAL_INNER)
        end

        def self.new_outer(cipher_suite:, config_id:, enc:, payload:)
          IllegalEchClientHello.new(
            type: ILLEGAL_OUTER,
            cipher_suite:,
            config_id:,
            enc:,
            payload:
          )
        end

        def serialize
          case @type
          when ILLEGAL_OUTER
            binary = @type + @cipher_suite.encode + @config_id.to_uint8 \
                     + @enc.prefix_uint16_length + @payload.prefix_uint16_length
          when ILLEGAL_INNER
            binary = @type
          else
            return super
          end

          @extension_type + binary.prefix_uint16_length
        end
      end
    end
  end
end
