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
      end
    end
  end
end
