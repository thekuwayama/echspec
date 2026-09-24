require_relative 'spec_helper'

RSpec.describe EchSpec::Spec::Spec5_1_10 do
  context 'remove_and_replace!' do
    def extensions(klass)
      exs, = EchSpec::TLS13Client.gen_ch_extensions('example.com')
      exs = klass.new(exs.values)
      exs << TTTLS13::Message::Extension::ECHClientHello.new_inner
      exs
    end

    def outer_extensions(replaced)
      replaced[TTTLS13::Message::ExtensionType::ECH_OUTER_EXTENSIONS].outer_extensions
    end

    let(:missing_referenced_extensions) do
      extensions(EchSpec::Spec::Spec5_1_10::MissingReferencedExtensions)
    end

    let(:duplicated_outer_extensions) do
      extensions(EchSpec::Spec::Spec5_1_10::DuplicatedOuterExtensions)
    end

    let(:referenced_encrypted_client_hello) do
      extensions(EchSpec::Spec::Spec5_1_10::ReferencedEncryptedClientHello)
    end

    let(:not_same_order_extensions) do
      extensions(EchSpec::Spec::Spec5_1_10::NotSameOrderExtensions)
    end

    it 'references key_share, which is missing in ClientHelloOuter' do
      expect(outer_extensions(missing_referenced_extensions.remove_and_replace!([]))).to eq [TTTLS13::Message::ExtensionType::KEY_SHARE]
      expect(missing_referenced_extensions.keys).not_to include TTTLS13::Message::ExtensionType::KEY_SHARE
    end

    it 'references key_share twice' do
      expect(outer_extensions(duplicated_outer_extensions.remove_and_replace!([]))).to eq [TTTLS13::Message::ExtensionType::KEY_SHARE] * 2
      expect(duplicated_outer_extensions.keys).to include TTTLS13::Message::ExtensionType::KEY_SHARE
    end

    it 'references encrypted_client_hello' do
      expect(outer_extensions(referenced_encrypted_client_hello.remove_and_replace!([]))).to eq [TTTLS13::Message::ExtensionType::ENCRYPTED_CLIENT_HELLO]
      expect(referenced_encrypted_client_hello.keys).to include TTTLS13::Message::ExtensionType::ENCRYPTED_CLIENT_HELLO
    end

    it 'references extensions in the different order from ClientHelloOuter' do
      replaced = not_same_order_extensions.remove_and_replace!([])
      referenced = [
        TTTLS13::Message::ExtensionType::KEY_SHARE,
        TTTLS13::Message::ExtensionType::SUPPORTED_VERSIONS
      ]
      expect(outer_extensions(replaced)).to match_array referenced
      expect(outer_extensions(replaced)).to eq not_same_order_extensions.keys.select { |k| referenced.include?(k) }.reverse
      expect(replaced.keys & referenced).to be_empty
    end
  end
end
