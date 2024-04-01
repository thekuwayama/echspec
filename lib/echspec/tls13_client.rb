module EchSpec
  module TLS13Client
    class Connection < TTTLS13::Connection
      # @param socket [Socket]
      # @param side [:client or :server]
      def initialize(socket, side)
        super(socket, side)
      end

      # @param cipher [TTTLS13::Cryptograph::$Object]
      #
      # @return [TTTLS13::Message::$Object]
      # @return [String]
      def recv_message(cipher)
        return @message_queue.shift unless @message_queue.empty?

        messages = nil
        orig_msgs = []
        loop do
          record, orig_msgs = recv_record(cipher)
          messages = record.messages
          break unless messages.empty?
        end

        @message_queue += messages[1..].zip(orig_msgs[1..])
        message = messages.first
        orig_msg = orig_msgs.first

        [message, orig_msg]
      end
    end

    class << self
      # @param hostname [String]
      #
      # @return [TTTLS13::Message::Extensions]
      # @return [Hash of NamedGroup => OpenSSL::PKey::EC.$Object]
      def gen_ch_extensions(hostname)
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
        groups = [
          TTTLS13::NamedGroup::SECP256R1,
          TTTLS13::NamedGroup::SECP384R1,
          TTTLS13::NamedGroup::SECP521R1
        ]
        exs << TTTLS13::Message::Extension::SupportedGroups.new(groups)

        # key_share
        key_share, priv_keys = TTTLS13::Message::Extension::KeyShare.gen_ch_key_share(
          groups
        )
        exs << key_share

        [exs, priv_keys]
      end

      # @param ch1 [TTTLS13::Message::ClientHello]
      # @param hrr [TTTLS13::Message::ServerHello]
      #
      # @return [TTTLS13::Message::Extensions]
      def gen_newch_extensions(ch1, hrr)
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

      # @param conf [ECHConfig::ECHConfigContents::HpkeKeyConfig]
      #
      # @return [Boolean]
      def select_ech_hpke_cipher_suite(conf)
        TTTLS13::STANDARD_CLIENT_ECH_HPKE_SYMMETRIC_CIPHER_SUITES.find do |cs|
          conf.cipher_suites.include?(cs)
        end
      end

      # @param socket [TCPSocket]
      # @param hostname [String]
      # @param ech_config [ECHConfig]
      #
      # @raise [EchSpec::Error::BeforeTargetSituationError]
      #
      # @return [EchSpec::TLS13Client::Connection]
      # @return [TTTLS13::Message::ClientHello]
      # @return [TTTLS13::Message::ServerHello] HelloRetryRequest
      # @return [TTTLS13::EchState]
      def recv_hrr(socket, hostname, ech_config)
        # send 1st ClientHello
        conn = TLS13Client::Connection.new(socket, :client)
        inner_ech = TTTLS13::Message::Extension::ECHClientHello.new_inner
        exs, = TLS13Client.gen_ch_extensions(hostname)
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

        selector = proc { |x| TLS13Client.select_ech_hpke_cipher_suite(x) }
        ch, _inner, ech_state = TTTLS13::Ech.offer_ech(inner, ech_config, selector)
        conn.send_record(
          TTTLS13::Message::Record.new(
            type: TTTLS13::Message::ContentType::HANDSHAKE,
            messages: [ch],
            cipher: TTTLS13::Cryptograph::Passer.new
          )
        )

        # receive HelloRetryRequest
        recv, = conn.recv_message(TTTLS13::Cryptograph::Passer.new)
        raise Error::BeforeTargetSituationError, 'not received HelloRetryRequest' \
          unless recv.is_a?(TTTLS13::Message::ServerHello) && recv.hrr?

        [conn, ch, recv, ech_state]
      end
    end
  end
end
