module EchSpec
  module Spec
    class Spec9
      # In the absence of an application profile standard specifying
      # otherwise, a compliant ECH application MUST implement the following
      # HPKE cipher suite:
      #
      # * KEM: DHKEM(X25519, HKDF-SHA256) (see Section 7.1 of [HPKE])
      # * KDF: HKDF-SHA256 (see Section 7.2 of [HPKE])
      # * AEAD: AES-128-GCM (see Section 7.3 of [HPKE])
      #
      # https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-9
      def self.is_compliant_echconfigs?(echconfigs)
        echconfigs.any? do |c|
          kconfig = c.echconfig_contents.key_config
          kconfig.kem_id.uint16 == 0x0020 &&
            kconfig.cipher_suites.any? do |cs|
            cs.kdf_id.uint16 == 0x0001 &&
              cs.aead_id.uint16 == 0x0001
          end
        end
      end

      def self.resolve_echconfigs(name)
        rr = Resolv::DNS.new.getresources(
          name,
          Resolv::DNS::Resource::IN::HTTPS
        )
        rr.first.svc_params['ech'].echconfiglist
      end

      def self.parse_pem(pem)
        s = pem.gsub(/-----(BEGIN|END) ECH CONFIGS-----/, '')
              .gsub("\n", '')
        b = Base64.decode64(s)
        raise 'failed to parse ECHConfigs' \
          unless b.length == b.slice(0, 2).unpack1('n') + 2

        begin
          echconfigs = ::ECHConfig.decode_vectors(b.slice(2..))
        rescue ::ECHConfig::Error
          raise 'failed to parse ECHConfigs'
        end
        echconfigs
      end
    end
  end
end
