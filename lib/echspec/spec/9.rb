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
      @section = '9'
      @description = 'MUST implement the following HPKE cipher suite: KEM: DHKEM(X25519, HKDF-SHA256), KDF: HKDF-SHA256 and AEAD: AES-128-GCM.'
      class << self
        # @return [String]
        def description
          "#{@description} [#{@section}]"
        end

        # @param fpath [String]
        # @param hostname [String]
        # @param force_compliant [Boolean]
        #
        # @return [EchSpec::Ok<ECHConfig> | Err]
        def try_get_ech_config(fpath, hostname, force_compliant)
          result = if fpath.nil?
                     resolve_ech_configs(hostname)
                   else
                     parse_pem(File.open(fpath).read)
                   end

          ech_configs = case result
                        in Ok(ech_configs)
                          ech_configs
                        in Err(details)
                          return result
                        end

          if force_compliant
            validate_compliant_ech_configs(ech_configs)
          else
            Ok.new(ech_configs.first)
          end
        end

        # @param [Array of ECHConfig]
        #
        # @return [EchSpec::Ok<ECHConfig> | Err]
        def validate_compliant_ech_configs(ech_configs)
          ech_config = ech_configs.find do |c|
            kconfig = c.echconfig_contents.key_config
            valid_kem_id = kconfig.kem_id.uint16 == 0x0020
            valid_cipher_suite = kconfig.cipher_suites.any? do |cs|
              cs.kdf_id.uint16 == 0x0001 && cs.aead_id.uint16 == 0x0001
            end

            valid_kem_id && valid_cipher_suite
          end
          return Ok.new(ech_config) unless ech_config.nil?

          Err.new('EchConfigs does NOT include HPKE cipher suite: KEM: DHKEM(X25519, HKDF-SHA256), KDF: HKDF-SHA256 and AEAD: AES-128-GCM.')
        end

        # @param hostname [String]
        #
        # @return [EchSpec::Ok<Array of ECHConfig> | Err]
        def resolve_ech_configs(hostname)
          begin
            rr = Resolv::DNS.new.getresource(
              hostname,
              Resolv::DNS::Resource::IN::HTTPS
            )
          rescue Resolv::ResolvError => e
            return Err.new(e.message)
          end

          return Err.new('HTTPS resource record does NOT have ech SvcParams') \
            if rr.svc_params['ech'].nil?

          Ok.new(rr.svc_params['ech'].echconfiglist)
        end

        # @param pem [String]
        #
        # @return [EchSpec::Ok<Array of ECHConfig> | Err]
        def parse_pem(pem)
          s = pem.gsub(/-----(BEGIN|END) ECH CONFIGS-----/, '')
                 .gsub("\n", '')
          b = Base64.decode64(s)
          return Err.new('failed to parse ECHConfigs') \
            unless b.length == b.slice(0, 2).unpack1('n') + 2

          begin
            ech_configs = ECHConfig.decode_vectors(b.slice(2..))
          rescue ECHConfig::Error
            return Err.new('failed to parse ECHConfigs')
          end

          Ok.new(ech_configs)
        end
      end
    end
  end
end
