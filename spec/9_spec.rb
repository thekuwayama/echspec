require_relative 'spec_helper'

RSpec.describe EchSpec::Spec::Spec9 do
  context 'parse_pem' do
    let(:pem) do
      File.open("#{__dir__}/../fixtures/echconfigs.pem").read
    end

    it 'could parse' do
      expect(EchSpec::Spec::Spec9.send(:parse_pem, pem)).to be_a EchSpec::Ok
    end
  end
end
