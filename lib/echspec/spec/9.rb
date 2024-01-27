module EchSpec
  module Spec
    class Spec9
      class << self
        # In the absence of an application profile standard specifying
        # otherwise, a compliant ECH application MUST implement the following
        # HPKE cipher suite:
        #
        # * KEM: DHKEM(X25519, HKDF-SHA256) (see Section 7.1 of [HPKE])
        # * KDF: HKDF-SHA256 (see Section 7.2 of [HPKE])
        # * AEAD: AES-128-GCM (see Section 7.3 of [HPKE])
        #
        # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-9

        # @param [Array of ECHConfig]
        #
        # @return [EchSpec::Ok | Err]
        def validate_compliant_echconfigs(echconfigs)
          echconfigs.any? do |c|
            kconfig = c.echconfig_contents.key_config
            valid_kem_id = kconfig.kem_id.uint16 == 0x0020
            valid_cipher_suite = kconfig.cipher_suites.any? do |cs|
              cs.kdf_id.uint16 == 0x0001 && cs.aead_id.uint16 == 0x0001
            end
            return Ok.new('OK') if valid_kem_id && valid_cipher_suite

            Err.new('NG')
          end
        end

        # @param hostname [String]
        #
        # @return [Array of ECHConfig]
        def resolve_echconfigs(hostname)
          rr = Resolv::DNS.new.getresources(
            hostname,
            Resolv::DNS::Resource::IN::HTTPS
          )
          rr.first.svc_params['ech'].echconfiglist
        end

        # @param pem [String]
        #
        # @return [Array of ECHConfig]
        def parse_pem(pem)
          s = pem.gsub(/-----(BEGIN|END) ECH CONFIGS-----/, '')
                .gsub("\n", '')
          b = Base64.decode64(s)
          raise 'failed to parse ECHConfigs' \
            unless b.length == b.slice(0, 2).unpack1('n') + 2

          begin
            echconfigs = ECHConfig.decode_vectors(b.slice(2..))
          rescue ECHConfig::Error
            raise 'failed to parse ECHConfigs'
          end
          echconfigs
        end
      end
    end
  end
end
