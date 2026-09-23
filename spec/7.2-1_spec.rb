require_relative 'spec_helper'

RSpec.describe EchSpec::Spec::Spec7_2_1 do
  context 'validate_sh_confirmation' do
    def sh(random)
      TTTLS13::Message::ServerHello.new(
        random:,
        legacy_session_id_echo: '',
        cipher_suite: TTTLS13::CipherSuite::TLS_AES_128_GCM_SHA256
      )
    end

    let(:confirmation) do
      "\xaa" * 8
    end

    let(:sh_with_confirmation) do
      sh(("\x02" * 24) + confirmation)
    end

    let(:sh_without_confirmation) do
      sh("\x02" * 32)
    end

    it 'returns Ok, if the last 8 bytes of ServerHello.random match accept_confirmation' do
      expect(EchSpec::Spec::Spec7_2_1.new.validate_sh_confirmation(confirmation, sh_with_confirmation)).to be_a EchSpec::Ok
    end

    it 'returns Err, if the last 8 bytes of ServerHello.random do not match accept_confirmation' do
      result = EchSpec::Spec::Spec7_2_1.new.validate_sh_confirmation(confirmation, sh_without_confirmation)
      expect(result).to be_a EchSpec::Err
      expect(result.details).to eq 'the last 8 bytes of ServerHello.random did not match accept_confirmation, although HelloRetryRequest confirmed ECH acceptance'
    end
  end
end
