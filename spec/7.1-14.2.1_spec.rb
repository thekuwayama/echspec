require_relative 'spec_helper'

RSpec.describe EchSpec::Spec::Spec7_1_14_2_1 do
  context 'validate_ee_ech' do
    def ee(extensions)
      TTTLS13::Message::EncryptedExtensions.new(
        TTTLS13::Message::Extensions.new(extensions)
      )
    end

    let(:ech_config) do
      EchSpec::EchConfig.gen_ech_config(OpenSSL::PKey.generate_key('X25519').raw_public_key)
    end

    let(:ee_with_retry_configs) do
      ee([TTTLS13::Message::Extension::ECHEncryptedExtensions.new([ech_config])])
    end

    let(:ee_with_empty_retry_configs) do
      ee([TTTLS13::Message::Extension::ECHEncryptedExtensions.new([])])
    end

    let(:ee_with_undecodable_ech) do
      ex = TTTLS13::Message::Extension::UnknownExtension.new(
        extension_type: TTTLS13::Message::ExtensionType::ENCRYPTED_CLIENT_HELLO,
        extension_data: "\x00\x01"
      )
      ee([ex])
    end

    let(:ee_without_ech) do
      ee([])
    end

    it 'returns Ok, if EncryptedExtensions includes "encrypted_client_hello" with "retry_configs"' do
      expect(EchSpec::Spec::Spec7_1_14_2_1.new.validate_ee_ech(ee_with_retry_configs)).to be_a EchSpec::Ok
    end

    it 'returns Err, if "retry_configs" is empty' do
      result = EchSpec::Spec::Spec7_1_14_2_1.new.validate_ee_ech(ee_with_empty_retry_configs)
      expect(result).to be_a EchSpec::Err
      expect(result.details).to eq 'EncryptedExtensions "encrypted_client_hello" extension did not have "retry_configs"'
    end

    it 'returns Err, if EncryptedExtensions includes undecodable "encrypted_client_hello"' do
      result = EchSpec::Spec::Spec7_1_14_2_1.new.validate_ee_ech(ee_with_undecodable_ech)
      expect(result).to be_a EchSpec::Err
      expect(result.details).to eq 'EncryptedExtensions "encrypted_client_hello" extension could not be decoded'
    end

    it 'returns Err, if EncryptedExtensions does not include "encrypted_client_hello"' do
      result = EchSpec::Spec::Spec7_1_14_2_1.new.validate_ee_ech(ee_without_ech)
      expect(result).to be_a EchSpec::Err
      expect(result.details).to eq 'EncryptedExtensions did not include "encrypted_client_hello" extension'
    end
  end
end
