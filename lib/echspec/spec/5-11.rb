module EchSpec
  module Spec
    class Spec5_11 < WithSocket
      # Finally, when the client offers the "encrypted_client_hello", if the
      # payload is the inner variant and the server responds with
      # HelloRetryRequest, it MUST include an "encrypted_client_hello"
      # extension with the following payload:
      #
      #     struct {
      #        opaque confirmation[8];
      #     } ECHHelloRetryRequest;
      #
      # The value of ECHHelloRetryRequest.confirmation is set to
      # hrr_accept_confirmation as described in Section 7.2.1.
      #
      # https://datatracker.ietf.org/doc/html/rfc9849#section-5-11

      # @return [EchSpec::SpecGroup]
      def self.spec_group
        SpecGroup.new(
          '5-11',
          [
            SpecCase.new(
              'MUST include an "encrypted_client_hello" extension with an 8-byte confirmation payload in HelloRetryRequest, if ClientHello offers the inner variant.',
              method(:validate_hrr_ech_length)
            )
          ]
        )
      end

      # @param hostname [String]
      # @param port [Integer]
      # @param ech_config [ECHConfig]
      #
      # @return [EchSpec::Ok | Err]
      def self.validate_hrr_ech_length(hostname, port, ech_config)
        Spec5_11.new.do_validate_hrr_ech_length(hostname, port, ech_config)
      end

      # @param hostname [String]
      # @param port [Integer]
      # @param ech_config [ECHConfig]
      #
      # @return [EchSpec::Ok | Err]
      def do_validate_hrr_ech_length(hostname, port, ech_config)
        with_socket(hostname, port) do |socket|
          _conn, _inner, _ch, hrr, = TLS13Client.recv_hrr(socket, hostname, ech_config, @stack)
          validate_hrr_ech(hrr)
        end
      end

      # @param hrr [TTTLS13::Message::ServerHello]
      #
      # @return [EchSpec::Ok | Err]
      def validate_hrr_ech(hrr)
        # Extensions#[] returns nil for UnknownExtension, so use super_fetch to
        # distinguish the extension whose length is not 8 from the missing one.
        ex = hrr.extensions.super_fetch(TTTLS13::Message::ExtensionType::ENCRYPTED_CLIENT_HELLO, nil)
        case ex
        in TTTLS13::Message::Extension::ECHHelloRetryRequest
          Ok.new(nil)
        in nil
          Err.new('HelloRetryRequest did not include "encrypted_client_hello" extension', message_stack)
        in TTTLS13::Message::Extension::UnknownExtension
          # tttls1.3 deserializes the extension whose length is not 8 as UnknownExtension
          Err.new("HelloRetryRequest \"encrypted_client_hello\" extension has #{ex.extension_data.length}-byte payload, expected 8 bytes", message_stack)
        end
      end
    end
  end
end
