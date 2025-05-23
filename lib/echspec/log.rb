module EchSpec
  module Log
    class MessageStack
      def initialize
        @stack = []
      end

      # @param msg [TTTLS13::Message::$Object]
      def <<(msg)
        @stack << msg
      end

      def marshal
        arr = []
        arr = @stack.reduce(arr) { |sum, msg| sum << "\"#{MessageStack.msg2name(msg)}\":#{MessageStack.obj2json(msg)}" }
        "{#{arr.reverse.join(',')}}"
      end

      # rubocop: disable Metrics/CyclomaticComplexity
      # rubocop: disable Metrics/PerceivedComplexity
      def self.msg2name(msg)
        case msg
        in TTTLS13::Message::ClientHello if msg.ch_inner?
          'ClientHelloInner'
        in TTTLS13::Message::ClientHello
          'ClientHello'
        in TTTLS13::Message::ServerHello if msg.hrr?
          'HelloRetryRequest'
        in TTTLS13::Message::ServerHello
          'ServerHello'
        in TTTLS13::Message::ChangeCipherSpec
          'ChangeCipherSpec'
        in TTTLS13::Message::EncryptedExtensions
          'EncryptedExtensions'
        in TTTLS13::Message::Certificate
          'Certificate'
        in TTTLS13::Message::CompressedCertificate
          'CompressedCertificate'
        in TTTLS13::Message::CertificateVerify
          'CertificateVerify'
        in TTTLS13::Message::Finished
          'Finished'
        in TTTLS13::Message::EndOfEarlyData
          'EndOfEarlyData'
        in TTTLS13::Message::NewSessionTicket
          'NewSessionTicket'
        in TTTLS13::Message::Alert
          'Alert'
        end
      end
      # rubocop: enable Metrics/CyclomaticComplexity
      # rubocop: enable Metrics/PerceivedComplexity

      # rubocop: disable Metrics/CyclomaticComplexity
      # rubocop: disable Metrics/PerceivedComplexity
      def self.obj2json(obj)
        case obj
        in OpenSSL::X509::Certificate
          obj.to_pem.gsub("\n", '\n')
        in Numeric | TrueClass | FalseClass
          obj.pretty_print_inspect
        in ''
          '""'
        in String
          "\"0x#{obj.unpack1('H*')}\""
        in NilClass
          'null'
        in Array
          s = obj.map { |i| obj2json(i) }.join(',')
          "[#{s}]"
        in Hash
          s = obj.map { |k, v| "#{obj2json(k)}:#{obj2json(v)}" }.join(',')
          "{#{s}}"
        in Object if !obj.instance_variables.empty?
          arr = obj.instance_variables.map do |i|
            k = i[1..]
            v = obj2json(obj.instance_variable_get(i))
            "\"#{k}\":#{v}"
          end
          "{#{arr.join(',')}}"
        else
          "\"$#{obj.class.name}\""
        end
      end
      # rubocop: enable Metrics/CyclomaticComplexity
      # rubocop: enable Metrics/PerceivedComplexity
    end
  end
end
