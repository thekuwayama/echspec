require_relative 'spec_helper'

RSpec.describe EchSpec::Spec::Spec5_11 do
  context 'validate_hrr_ech' do
    def hrr(extensions)
      TTTLS13::Message::ServerHello.new(
        random: TTTLS13::Message::HRR_RANDOM,
        legacy_session_id_echo: '',
        cipher_suite: TTTLS13::CipherSuite::TLS_AES_128_GCM_SHA256,
        extensions: TTTLS13::Message::Extensions.new(extensions)
      )
    end

    let(:spec) do
      EchSpec::Spec::Spec5_11.new
    end

    it 'returns Ok, if HelloRetryRequest includes 8-byte "encrypted_client_hello"' do
      ex = TTTLS13::Message::Extension::ECHHelloRetryRequest.new("\x00" * 8)
      expect(spec.validate_hrr_ech(hrr([ex]))).to be_a EchSpec::Ok
    end

    it 'returns Err, if HelloRetryRequest includes 7-byte "encrypted_client_hello"' do
      ex = TTTLS13::Message::Extension::UnknownExtension.new(
        extension_type: TTTLS13::Message::ExtensionType::ENCRYPTED_CLIENT_HELLO,
        extension_data: "\x00" * 7
      )
      result = spec.validate_hrr_ech(hrr([ex]))
      expect(result).to be_a EchSpec::Err
      expect(result.details).to include '7-byte'
    end

    it 'returns Err, if HelloRetryRequest does not include "encrypted_client_hello"' do
      result = spec.validate_hrr_ech(hrr([]))
      expect(result).to be_a EchSpec::Err
      expect(result.details).to include 'did not include'
    end
  end
end
