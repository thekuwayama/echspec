module EchSpec
  module Spec
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
      # @param record [TTTLS13::Message::Record]
      # @param desc [Symbol]
      #
      # @return [Boolean]
      def expect_alert(msg, desc)
        msg.is_a?(TTTLS13::Message::Alert) &&
          msg.description == TTTLS13::Message::ALERT_DESCRIPTION[desc]
      end

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

      # @param conf [ECHConfig::ECHConfigContents::HpkeKeyConfig]
      #
      # @return [Boolean]
      def select_ech_hpke_cipher_suite(conf)
        TTTLS13::STANDARD_CLIENT_ECH_HPKE_SYMMETRIC_CIPHER_SUITES.find do |cs|
          conf.cipher_suites.include?(cs)
        end
      end
    end
  end
end

Dir[File.dirname(__FILE__) + '/spec/*.rb'].sort.each { |f| require f }

module EchSpec
  module Spec
    class << self
      using Refinements

      # @param result [EchSpec::Ok | Err]
      def print_result(result)
        case result
        in Ok(message)
          puts message.green
        in Err(message)
          puts message.red
        end
      end

      # @param fpath [String]
      # @param port [Integer]
      # @param hostname [String]
      def run(fpath, port, hostname)
        TTTLS13::Logging.logger.level = Logger::WARN

        # 9
        echconfigs = if fpath.nil?
                       Spec9.resolve_echconfigs(hostname)
                     else
                       Spec9.parse_pem(File.open(fpath).read)
                     end
        Spec9.validate_compliant_echconfigs(echconfigs).tap { |x| print_result(x) }
        ech_config = echconfigs.first

        # 7-2.3.1
        Spec7_2_3_1.validate_illegal_ech_type(hostname, port, ech_config).each { |x| print_result(x) }

        # 7.1.1-2
        Spec7_1_1_2.validate_hrr_missing_ech(hostname, port, ech_config).tap { |x| print_result(x) }

        # 7.1-10
        Spec7_1_10.validate_ech_with_tls12(hostname, port, ech_config).tap { |x| print_result(x) }

        # 7.1-13.2.1
        Spec7_1_13_2_1.valid_ee_retry_configs(hostname, port).tap { |x| print_result(x) }
      end
    end
  end
end
