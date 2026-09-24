require_relative 'spec_helper'

RSpec.describe EchSpec::Spec::Spec5_1_9::NonzeroPaddingEch do
  context 'padding_encoded_ch_inner' do
    def padding(len)
      s = 'a' * len
      padded = EchSpec::Spec::Spec5_1_9::NonzeroPaddingEch.padding_encoded_ch_inner(s, 11, 11)
      expect(padded).to start_with s
      padded[len..]
    end

    [31, 33].each do |len|
      it "pads with non-zero values, if the length of EncodedClientHelloInner is #{len}" do
        expect(padding(len)).not_to be_empty
        expect(padding(len).bytes.uniq).to eq [0x11]
      end
    end

    it 'pads 32 bytes with non-zero values, if TTTLS13::Ech does not pad' do
      expect(TTTLS13::Ech.padding_encoded_ch_inner('a' * 32, 11, 11).length).to eq 32
      expect(padding(32)).to eq "\x11" * 32
    end
  end
end
