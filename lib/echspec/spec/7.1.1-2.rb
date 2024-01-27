module EchSpec
  module Spec
    class Spec7_1_1_2
      class << self
        # If the client-facing server accepted ECH, it checks the second
        # ClientHelloOuter also contains the "encrypted_client_hello"
        # extension. If not, it MUST abort the handshake with a
        # "missing_extension" alert. Otherwise, it checks that
        # ECHClientHello.cipher_suite and ECHClientHello.config_id are
        # unchanged, and that ECHClientHello.enc is empty. If not, it MUST
        # abort the handshake with an "illegal_parameter" alert.
        #
        # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-7.1.1-2

        # @param hostname [String]
        # @param port [Integer]
        # @param ech_config [ECHConfig]
        #
        # @return [EchSpec::Ok or Err]
        def validate_hrr_missing_ech(hostname, port, ech_config)
          socket = TCPSocket.new(hostname, port)
          recv = send_hrr_missing_ech(socket, hostname, ech_config)
          socket.close
          return Err.new('NG') unless Spec.expect_alert(recv, :missing_extension)

          Ok.new('OK')
        end

        def send_hrr_missing_ech(socket, hostname, ech_config)
          # send 1st ClientHello
          conn = TTTLS13::Connection.new(socket, :client)
          inner_ech = TTTLS13::Message::Extension::ECHClientHello.new_inner
          exs = Spec.gen_ch_extensions(hostname)
          exs.delete(TTTLS13::Message::ExtensionType::KEY_SHARE) # for HRR
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

          # receive HelloRetryRequest
          recv, = conn.recv_record(TTTLS13::Cryptograph::Passer.new)
          raise 'not received HelloRetryRequest' \
            unless recv.messages.first.hrr?

          # send 2nd ClientHello without ech
          ch1 = ch
          hrr = recv.messages.first
          new_exs = gen_new_ch_extensions(ch1, hrr)
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

          # skip ChangeCipherSpec
          recv, = conn.recv_record(TTTLS13::Cryptograph::Passer.new)
          recv, = conn.recv_record(TTTLS13::Cryptograph::Passer.new) \
            if recv.type == TTTLS13::Message::ContentType::CCS
          recv
        end

        def gen_new_ch_extensions(ch1, hrr)
          exs = TTTLS13::Message::Extensions.new
          # key_share
          if hrr.extensions.include?(TTTLS13::Message::ExtensionType::KEY_SHARE)
            group = hrr.extensions[TTTLS13::Message::ExtensionType::KEY_SHARE]
                       .key_share_entry.first.group
            key_share, = TTTLS13::Message::Extension::KeyShare.gen_ch_key_share([group])
            exs << key_share
          end

          # cookie
          exs << hrr.extensions[TTTLS13::Message::ExtensionType::COOKIE] \
            if hrr.extensions.include?(TTTLS13::Message::ExtensionType::COOKIE)

          ch1.extensions.merge(exs)
        end
      end
    end
  end
end
