module EchSpec
  module Spec
    class Spec7_2_3_1
      class << self
        # * Otherwise, if ECHClientHello.type is not a valid
        #   ECHClientHelloType, then the server MUST abort with an
        #   "illegal_parameter" alert.
        #
        # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-7-2.3.1

        # @param hostname [String]
        # @param port [Integer]
        # @param echconfig [ECHConfig]
        #
        # @return [EchSpec::Ok or Err]
        def validate_illegal_inner_ech_type(hostname, port, echconfig)
          socket = TCPSocket.new(hostname, port)
          recv = send_illegal_inner_ech_type(socket, hostname, echconfig)
          socket.close
          return Ok.new('OK') if Spec.expect_alert(recv, :illegal_parameter)

          Err.new('NG')
        end

        # @param socket [TCPSocket]
        # @param hostname [String]
        # @param echconfig [ECHConfig]
        #
        # @return [TTTLS13::Message::Record]
        def send_illegal_inner_ech_type(socket, hostname, echconfig)
          inner_ech = IllegalEchClientHello.new_inner
          exs = gen_extensions(hostname)
          exs.merge(TTTLS13::Message::ExtensionType::ENCRYPTED_CLIENT_HELLO => inner_ech)
          conn = TTTLS13::Connection.new(socket, :client)
          inner = TTTLS13::Message::ClientHello.new(
            cipher_suites: TTTLS13::CipherSuites.new(
              [
                TTTLS13::CipherSuite::TLS_AES_256_GCM_SHA384,
                TTTLS13::CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
                TTTLS13::CipherSuite::TLS_AES_128_GCM_SHA256
              ]
            ),
            extensions: exs
          )

          selector = method(:select_ech_hpke_cipher_suite)
          ch, = TTTLS13::Ech.offer_ech(inner, echconfig, selector)
          conn.send_record(TTTLS13::Message::Record.new(
            type: TTTLS13::Message::ContentType::HANDSHAKE,
            messages: [ch],
            cipher: TTTLS13::Cryptograph::Passer.new
          ))
          recv, = conn.recv_record(TTTLS13::Cryptograph::Passer.new)
          recv
        end

        private

        def gen_extensions(hostname)
          exs = TTTLS13::Message::Extensions.new
          # server_name
          exs << TTTLS13::Message::Extension::ServerName.new(hostname)

          # supported_versions: only TLS 1.3
          exs << TTTLS13::Message::Extension::SupportedVersions.new(
            msg_type: TTTLS13::Message::HandshakeType::CLIENT_HELLO
          )

          # signature_algorithms
          exs << TTTLS13::Message::Extension::SignatureAlgorithms.new(
            [
              TTTLS13::SignatureScheme::ECDSA_SECP256R1_SHA256,
              TTTLS13::SignatureScheme::ECDSA_SECP384R1_SHA384,
              TTTLS13::SignatureScheme::ECDSA_SECP521R1_SHA512,
              TTTLS13::SignatureScheme::RSA_PSS_RSAE_SHA256,
              TTTLS13::SignatureScheme::RSA_PSS_RSAE_SHA384,
              TTTLS13::SignatureScheme::RSA_PSS_RSAE_SHA512,
              TTTLS13::SignatureScheme::RSA_PKCS1_SHA256,
              TTTLS13::SignatureScheme::RSA_PKCS1_SHA384,
              TTTLS13::SignatureScheme::RSA_PKCS1_SHA512
            ]
          )

          # supported_groups
          exs << TTTLS13::Message::Extension::SupportedGroups.new(
            [
              TTTLS13::NamedGroup::SECP256R1,
              TTTLS13::NamedGroup::SECP384R1,
              TTTLS13::NamedGroup::SECP521R1
            ]
          )

          exs
        end

        def select_ech_hpke_cipher_suite(conf)
          TTTLS13::STANDARD_CLIENT_ECH_HPKE_SYMMETRIC_CIPHER_SUITES.find do |cs|
            conf.cipher_suites.include?(cs)
          end
        end

        ILLEGAL_OUTER = "\x02"
        ILLEGAL_INNER = "\x03"

        class IllegalEchClientHello < TTTLS13::Message::Extension::ECHClientHello
          using TTTLS13::Refinements

          def self.new_inner
            TTTLS13::Message::Extension::ECHClientHello.new(type: ILLEGAL_INNER)
          end

          def serialize
            case @type
            when ILLEGAL_OUTER
              binary = @type + @cipher_suite.encode + @config_id.to_uint8 \
                       + @enc.prefix_uint16_length + @payload.prefix_uint16_length
            when ILLEGAL_INNER
              binary = @type
            else
              raise 'failed to serialize ECHClientHello'
            end

            @extension_type + binary.prefix_uint16_length
          end
        end
      end
    end
  end
end
