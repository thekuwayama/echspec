module EchSpec
  module Spec
    class Spec7_1_10
      class << self
        # Upon determining the ClientHelloInner, the client-facing server
        # checks that the message includes a well-formed
        # "encrypted_client_hello" extension of type inner and that it does not
        # offer TLS 1.2 or below. If either of these checks fails, the client-
        # facing server MUST abort with an "illegal_parameter" alert.
        #
        # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-7.1-10

        # @param hostname [String]
        # @param port [Integer]
        # @param ech_config [ECHConfig]
        #
        # @return [EchSpec::Ok | Err]
        def validate_ech_with_tls12(hostname, port, ech_config)
          socket = TCPSocket.new(hostname, port)
          recv = send_ch_ech_with_tls12(socket, hostname, ech_config)
          socket.close
          return Err.new('NG') unless Spec.expect_alert(recv, :illegal_parameter)

          Ok.new('OK')
        end

        def send_ch_ech_with_tls12(socket, hostname, ech_config)
          conn = TTTLS13::Connection.new(socket, :client)
          inner_ech = TTTLS13::Message::Extension::ECHClientHello.new_inner
          exs = Spec.gen_ch_extensions(hostname)
          # supported_versions: only TLS 1.2
          versions = TTTLS13::Message::Extension::SupportedVersions.new(
            msg_type: TTTLS13::Message::HandshakeType::CLIENT_HELLO,
            versions: [TTTLS13::Message::ProtocolVersion::TLS_1_3]
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
          selector = proc { |x| Spec.select_ech_hpke_cipher_suite(x) }
          ch, = TTTLS13::Ech.offer_ech(inner, ech_config, selector)
          conn.send_record(
            TTTLS13::Message::Record.new(
              type: TTTLS13::Message::ContentType::HANDSHAKE,
              messages: [ch],
              cipher: TTTLS13::Cryptograph::Passer.new
            )
          )
          recv, = conn.recv_record(TTTLS13::Cryptograph::Passer.new)
          recv
        end
      end
    end
  end
end
