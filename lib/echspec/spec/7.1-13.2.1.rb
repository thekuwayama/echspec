module EchSpec
  module Spec
    class Spec7_1_13_2_1
      class << self
        # Otherwise, if all candidate ECHConfig values fail to decrypt the
        # extension, the client-facing server MUST ignore the extension and
        # proceed with the connection using ClientHelloOuter, with the
        # following modifications:
        #
        # * If the server is configured with any ECHConfigs, it MUST include
        #   the "encrypted_client_hello" extension in its EncryptedExtensions
        #   with the "retry_configs" field set to one or more ECHConfig
        #   structures with up-to-date keys.
        #
        # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-7.1-13.2.1
      end
    end
  end
end
