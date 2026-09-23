require_relative 'spec_helper'

RSpec.describe EchSpec::Spec::Spec7_2_1 do
  context 'validate_sh_confirmation' do
    def ch(random)
      TTTLS13::Message::ClientHello.new(
        random:,
        cipher_suites: TTTLS13::CipherSuites.new([TTTLS13::CipherSuite::TLS_AES_128_GCM_SHA256])
      )
    end

    def sh(random)
      TTTLS13::Message::ServerHello.new(
        random:,
        legacy_session_id_echo: '',
        cipher_suite: TTTLS13::CipherSuite::TLS_AES_128_GCM_SHA256
      )
    end

    let(:inner1) do
      ch("\x01" * 32)
    end

    let(:hrr) do
      h = TTTLS13::Message::ServerHello.new(
        random: TTTLS13::Message::HRR_RANDOM,
        legacy_session_id_echo: '',
        cipher_suite: TTTLS13::CipherSuite::TLS_AES_128_GCM_SHA256,
        extensions: TTTLS13::Message::Extensions.new(
          [TTTLS13::Message::Extension::ECHHelloRetryRequest.new("\x00" * 8)]
        )
      )
      TTTLS13::Message::ServerHello.deserialize(h.serialize)
    end

    let(:inner2) do
      ch("\x01" * 32)
    end

    # ServerHello.random whose last 8 bytes are accept_confirmation
    let(:sh_with_confirmation) do
      zeroed = sh("\x02" * 24 + "\x00" * 8)
      confirmation = EchSpec::TLS13Client.accept_confirmation(inner1, hrr, hrr.serialize, inner2, zeroed, zeroed.serialize)
      sh("\x02" * 24 + confirmation)
    end

    let(:sh_without_confirmation) do
      sh("\x02" * 32)
    end

    it 'returns Ok, if ServerHello.random includes accept_confirmation' do
      expected = EchSpec::TLS13Client.accept_confirmation(
        inner1, hrr, hrr.serialize, inner2, sh_with_confirmation, sh_with_confirmation.serialize
      )
      expect(EchSpec::Spec::Spec7_2_1.new.validate_sh_confirmation(expected, sh_with_confirmation)).to be_a EchSpec::Ok
    end

    it 'returns Err, if ServerHello.random does not include accept_confirmation' do
      expected = EchSpec::TLS13Client.accept_confirmation(
        inner1, hrr, hrr.serialize, inner2, sh_without_confirmation, sh_without_confirmation.serialize
      )
      result = EchSpec::Spec::Spec7_2_1.new.validate_sh_confirmation(expected, sh_without_confirmation)
      expect(result).to be_a EchSpec::Err
      expect(result.details).to eq 'ServerHello.random did not include accept_confirmation, although HelloRetryRequest confirmed ECH acceptance'
    end
  end
end
