require_relative 'spec_helper'

RSpec.describe EchSpec::Log::MessageStack do
  context 'obj2json' do
    let(:crt) do
      File.open("#{__dir__}/../fixtures/server.crt").read
    end

    it 'should convert' do
      expect(EchSpec::Log::MessageStack.obj2json(OpenSSL::X509::Certificate.new(crt)))
        .to eq "#{crt.split("\n").join('\n')}\\n"
    end

    it 'should convert' do
      expect(EchSpec::Log::MessageStack.obj2json(1)).to eq '1'
    end

    it 'should convert' do
      expect(EchSpec::Log::MessageStack.obj2json(0.1)).to eq '0.1'
    end

    it 'should convert' do
      expect(EchSpec::Log::MessageStack.obj2json(true)).to eq 'true'
    end

    it 'should convert' do
      expect(EchSpec::Log::MessageStack.obj2json(false)).to eq 'false'
    end

    it 'should convert' do
      expect(EchSpec::Log::MessageStack.obj2json('')).to eq '""'
    end

    it 'should convert' do
      expect(EchSpec::Log::MessageStack.obj2json('string')).to eq '"0x737472696e67"'
    end

    it 'should convert' do
      expect(EchSpec::Log::MessageStack.obj2json(nil)).to eq 'null'
    end

    it 'should convert' do
      expect(EchSpec::Log::MessageStack.obj2json([1, true, '', 'string', nil])).to eq '[1,true,"","0x737472696e67",null]'
    end

    it 'should convert' do
      expect(EchSpec::Log::MessageStack.obj2json(1 => true, '' => 'string', nil => [])).to eq '{1:true,"":"0x737472696e67",null:[]}'
    end

    it 'should convert' do
      expect(EchSpec::Log::MessageStack.obj2json(C.new('string'))).to eq '{"name":"0x737472696e67"}'
    end

    it 'should convert' do
      expect(EchSpec::Log::MessageStack.obj2json(D.new)).to eq '"$D"'
    end
  end
end
