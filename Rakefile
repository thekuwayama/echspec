require 'bundler/gem_tasks'
require 'ech_config'
require 'hpke'
require 'openssl'
require 'rspec/core/rake_task'
require 'rubocop/rake_task'

RuboCop::RakeTask.new
RSpec::Core::RakeTask.new(:spec)

TMP_DIR    = "#{__dir__}/tmp".freeze
ECHCONFIGS = "#{TMP_DIR}/echconfigs.pem".freeze

directory TMP_DIR

file ECHCONFIGS => TMP_DIR do
  puts "generate #{ECHCONFIGS}..."

  key = OpenSSL::PKey.generate_key('X25519')
  echconfigs = ECHConfigList.new(
    [
      ECHConfig.new(
        "\xfe\x0d".b,
        ECHConfig::ECHConfigContents.new(
          ECHConfig::ECHConfigContents::HpkeKeyConfig.new(
            123,
            ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeKemId.new(HPKE::DHKEM_X25519_HKDF_SHA256),
            ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkePublicKey.new(key.raw_public_key),
            [
              ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeSymmetricCipherSuite.new(
                ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeSymmetricCipherSuite::HpkeKdfId.new(HPKE::HKDF_SHA256),
                ECHConfig::ECHConfigContents::HpkeKeyConfig::HpkeSymmetricCipherSuite::HpkeAeadId.new(HPKE::AES_128_GCM)
              )
            ]
          ),
          32,
          'localhost'.b,
          ECHConfig::ECHConfigContents::Extensions.new('')
        )
      )
    ]
  )
  File.write(ECHCONFIGS, key.private_to_pem + echconfigs.to_pem)
end

desc 'generate echconfigs file'
task gen_echconfigs: ECHCONFIGS

task default: %i[rubocop spec]
