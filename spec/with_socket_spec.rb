require_relative 'spec_helper'

module EchSpec
  module Spec
    class SpecX < WithSocket
      def validate(hostname, port)
        with_socket(hostname, port) do |_socket|
          # not return
        end
      end
    end

    class SpecY < WithSocket
      def validate(hostname, port)
        with_socket(hostname, port) do |_socket|
          return EchSpec::Ok.new(1)
        end
      end
    end

    class SpecZ < WithSocket
      def validate(hostname, port)
        with_socket(hostname, port) do |_socket|
          msg = TTTLS13::Message::Alert.new(
            level: TTTLS13::Message::AlertLevel::FATAL,
            description: "\x0a"
          )
          return EchSpec::Err.new('details', [msg])
        end
      end
    end

    class SpecW < WithSocket
      def validate(hostname, port)
        with_socket(hostname, port) do |_socket|
          raise EchSpec::Error::BeforeTargetSituationError, 'not received ClientHello'
        end
      end
    end
  end
end

RSpec.describe EchSpec::Spec::WithSocket do
  context 'with_socket' do
    before do
      socket = StringIO.new
      allow(TCPSocket).to receive(:new).and_return(socket)
    end

    it 'should return Ok(nil)' do
      result = EchSpec::Spec::SpecX.new.validate('localhost', 4433)
      expect(result).to be_a EchSpec::Ok
      expect(result.obj).to eq nil
    end

    it 'should return Ok(1)' do
      result = EchSpec::Spec::SpecY.new.validate('localhost', 4433)
      expect(result).to be_a EchSpec::Ok
      expect(result.obj).to eq 1
    end

    it 'should return Err(details, message_stack)' do
      result = EchSpec::Spec::SpecZ.new.validate('localhost', 4433)
      expect(result).to be_a EchSpec::Err
      expect(result.details).to eq 'details'
      expect(result.message_stack.length).to be 1
      expect(result.message_stack.first.level).to be TTTLS13::Message::AlertLevel::FATAL
      expect(result.message_stack.first.description).to eq "\x0a"
    end

    it 'should return Err(details, message_stack), raised BeforeTargetSituationError' do
      result = EchSpec::Spec::SpecW.new.validate('localhost', 4433)
      expect(result).to be_a EchSpec::Err
      expect(result.details).to eq 'not received ClientHello'
      expect(result.message_stack).to eq '{}'
    end
  end
end
