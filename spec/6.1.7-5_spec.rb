require_relative 'spec_helper'

RSpec.describe EchSpec::Spec::Spec6_1_7_5 do
  context 'valid_public_name?' do
    [
      'example.com',
      'localhost',
      'a-b.example',
      'xn--bcher-kva.example',
      "#{'a' * 63}.example",
      '1.2.3.4'
    ].each do |public_name|
      it "returns true for #{public_name.inspect}" do
        expect(EchSpec::Spec::Spec6_1_7_5.valid_public_name?(public_name)).to be true
      end
    end

    [
      '',
      '.',
      '.example.com',
      'example.com.',
      'a..b',
      '-a.com',
      'a-.com',
      "#{'a' * 64}.example",
      'exa_mple.com',
      'exa mple.com',
      'exämple.com'
    ].each do |public_name|
      it "returns false for #{public_name.inspect}" do
        expect(EchSpec::Spec::Spec6_1_7_5.valid_public_name?(public_name)).to be false
      end
    end
  end

  context 'ipv4_like?' do
    [
      '1.2.3.4',
      'example.123',
      'example.0x1f',
      'example.0X1F',
      'example.0x',
      '0X'
    ].each do |public_name|
      it "returns true for #{public_name.inspect}" do
        expect(EchSpec::Spec::Spec6_1_7_5.ipv4_like?(public_name)).to be true
      end
    end

    [
      'example.com',
      'localhost',
      '123.example',
      'example.0xg',
      'example.1a',
      ''
    ].each do |public_name|
      it "returns false for #{public_name.inspect}" do
        expect(EchSpec::Spec::Spec6_1_7_5.ipv4_like?(public_name)).to be false
      end
    end
  end

  context 'spec_group' do
    let(:ech_config) do
      pem = File.open("#{__dir__}/../fixtures/echconfigs.pem").read
      EchSpec::Spec::Spec9.send(:parse_pem, pem).obj.first
    end

    it 'passes all spec cases for fixtures/echconfigs.pem' do
      EchSpec::Spec::Spec6_1_7_5.spec_group.spec_cases.each do |sc|
        expect(sc.method.call('localhost', 4433, ech_config)).to be_a EchSpec::Ok
      end
    end
  end
end
