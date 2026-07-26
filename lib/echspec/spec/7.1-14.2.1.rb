module EchSpec
  module Spec
    class Spec7_1_14_2_1 < WithSocket
      # Otherwise, if all candidate ECHConfig values fail to decrypt the
      # extension, the client-facing server MUST ignore the extension and
      # proceed with the connection using ClientHelloOuter with the following
      # modifications:
      #
      # * If the server is configured with any ECHConfigs, it MUST include
      #   the "encrypted_client_hello" extension in its EncryptedExtensions
      #   with the "retry_configs" field set to one or more ECHConfig
      #   structures with up-to-date keys. Servers MAY supply multiple
      #   ECHConfig values of different versions. This allows a server to
      #   support multiple versions at once.
      #
      # https://datatracker.ietf.org/doc/html/rfc9849#section-7.1-14.2.1

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
        Spec7_1_14_2_1.new.do_validate_ee_retry_configs(hostname, port)
      end

      # @param hostname [String]
      # @param port [Integer]
      #
      # @return [EchSpec::Ok | Err]
      def do_validate_ee_retry_configs(hostname, port)
        with_socket(hostname, port) do |socket|
          recv = TLS13Client.send_ch_with_greased_ech(socket, hostname, @stack)
          ex = recv.extensions[TTTLS13::Message::ExtensionType::ENCRYPTED_CLIENT_HELLO]
          return Err.new('did not send expected alert: encrypted_client_hello', message_stack) \
            unless ex.is_a?(TTTLS13::Message::Extension::ECHEncryptedExtensions)
          return Err.new('ECHConfigs did not have "retry_configs"', message_stack) \
            if ex.retry_configs.nil? || ex.retry_configs.empty?

          Ok.new(nil)
        end
      end
    end
  end
end
