require_relative 'spec_helper'

RSpec.describe EchSpec::Spec::Spec9 do
  let(:public_key) do
    OpenSSL::PKey.generate_key('X25519').raw_public_key
  end

  let(:ech_config_list) do
    ECHConfigList.new([EchSpec::CLI::GenConfigs.gen_ech_config(public_key)]).encode
  end

  # ECHConfigList whose length field is 1 byte longer than its contents
  let(:mismatched_ech_config_list) do
    [ech_config_list.length - 1].pack('n') + ech_config_list[2..]
  end

  # ECHConfigList shorter than its 2-byte length field
  let(:too_short_ech_config_list) do
    "\x00"
  end

  context 'parse_pem' do
    let(:pem) do
      File.open("#{__dir__}/../fixtures/echconfigs.pem").read
    end

    let(:pem_without_ech_config) do
      "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n"
    end

    let(:pem_with_mismatched_length) do
      "-----BEGIN ECHCONFIG-----\n#{Base64.strict_encode64(mismatched_ech_config_list)}\n-----END ECHCONFIG-----\n"
    end

    let(:pem_with_too_short_length) do
      "-----BEGIN ECHCONFIG-----\n#{Base64.strict_encode64(too_short_ech_config_list)}\n-----END ECHCONFIG-----\n"
    end

    it 'could parse' do
      expect(EchSpec::Spec::Spec9.send(:parse_pem, pem)).to be_a EchSpec::Ok
    end

    it 'returns Err, if PEM does not include ECHConfig' do
      result = EchSpec::Spec::Spec9.send(:parse_pem, pem_without_ech_config)
      expect(result).to be_a EchSpec::Err
      expect(result.details).to start_with 'Failed to parse ECHConfig PEM file'
    end

    it 'returns Err, if the length of ECHConfigList mismatches' do
      result = EchSpec::Spec::Spec9.send(:parse_pem, pem_with_mismatched_length)
      expect(result).to be_a EchSpec::Err
      expect(result.details).to eq 'Failed to parse ECHConfig on the PEM file.'
    end

    it 'returns Err, if ECHConfigList is shorter than 2 bytes' do
      result = EchSpec::Spec::Spec9.send(:parse_pem, pem_with_too_short_length)
      expect(result).to be_a EchSpec::Err
      expect(result.details).to eq 'Failed to parse ECHConfig on the PEM file.'
    end
  end

  context 'validate_compliant_ech_configs' do
    let(:compliant) do
      EchSpec::CLI::GenConfigs.gen_ech_config(public_key)
    end

    let(:non_compliant_kem) do
      EchSpec::CLI::GenConfigs.gen_ech_config(public_key, kem_id: HPKE::DHKEM_P256_HKDF_SHA256)
    end

    let(:non_compliant_aead) do
      EchSpec::CLI::GenConfigs.gen_ech_config(public_key, aead_id: HPKE::CHACHA20_POLY1305)
    end

    it 'returns Ok with the compliant ECHConfig' do
      result = EchSpec::Spec::Spec9.validate_compliant_ech_configs([non_compliant_kem, compliant])
      expect(result).to be_a EchSpec::Ok
      expect(result.obj).to be compliant
    end

    it 'returns Err, if KEM is not DHKEM(X25519, HKDF-SHA256)' do
      result = EchSpec::Spec::Spec9.validate_compliant_ech_configs([non_compliant_kem])
      expect(result).to be_a EchSpec::Err
      expect(result.details).to eq 'ECHConfigs does NOT include HPKE cipher suite: KEM: DHKEM(X25519, HKDF-SHA256), KDF: HKDF-SHA256 and AEAD: AES-128-GCM.'
    end

    it 'returns Err, if AEAD is not AES-128-GCM' do
      expect(EchSpec::Spec::Spec9.validate_compliant_ech_configs([non_compliant_aead])).to be_a EchSpec::Err
    end
  end

  context 'parse_origin_svcb' do
    let(:body_with_ech) do
      JSON.generate({ endpoints: [{ params: { ech: Base64.strict_encode64(ech_config_list) } }] })
    end

    let(:body_with_mismatched_length) do
      JSON.generate({ endpoints: [{ params: { ech: Base64.strict_encode64(mismatched_ech_config_list) } }] })
    end

    let(:body_with_too_short_length) do
      JSON.generate({ endpoints: [{ params: { ech: Base64.strict_encode64(too_short_ech_config_list) } }] })
    end

    let(:body_without_ech) do
      JSON.generate({ endpoints: [{ params: { alpn: ['h2'] } }] })
    end

    let(:body_not_json) do
      'not json'
    end

    it 'returns Ok, if the origin-svcb well-known resource has ech SvcParams' do
      result = EchSpec::Spec::Spec9.parse_origin_svcb(body_with_ech)
      expect(result).to be_a EchSpec::Ok
      expect(result.obj.length).to eq 1
    end

    it 'returns Err, if the length of ECHConfigList mismatches' do
      result = EchSpec::Spec::Spec9.parse_origin_svcb(body_with_mismatched_length)
      expect(result).to be_a EchSpec::Err
      expect(result.details).to eq 'Failed to parse ECHConfig on the origin-svcb well-known resource.'
    end

    it 'returns Err, if ECHConfigList is shorter than 2 bytes' do
      result = EchSpec::Spec::Spec9.parse_origin_svcb(body_with_too_short_length)
      expect(result).to be_a EchSpec::Err
      expect(result.details).to eq 'Failed to parse ECHConfig on the origin-svcb well-known resource.'
    end

    it 'returns Err, if the origin-svcb well-known resource does not have ech SvcParams' do
      result = EchSpec::Spec::Spec9.parse_origin_svcb(body_without_ech)
      expect(result).to be_a EchSpec::Err
      expect(result.details).to eq 'The origin-svcb well-known resource does NOT have ech SvcParams.'
    end

    it 'returns Err, if the body is not JSON' do
      expect(EchSpec::Spec::Spec9.parse_origin_svcb(body_not_json)).to be_a EchSpec::Err
    end
  end
end
