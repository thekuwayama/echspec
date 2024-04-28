module EchSpec
  module Log
    class MessageStack
      def initialize
        @stack = []
      end

      # @param inner [TTTLS13::Message::ClientHello]
      def ch_inner(ch_inner)
        @ch_inner = ch_inner
      end

      # @param msg [TTTLS13::Message::$Object]
      def <<(msg)
        @stack << msg
      end

      def marshal
        arr = []
        arr << "\"ClientHelloInner\":#{obj2json(@ch_inner)}" unless @ch_inner.nil?
        arr = @stack.reduce(arr) { |sum, msg| sum << "\"#{msg2name(msg)}\":#{obj2json(msg)}" }
        "{#{arr.reverse.join(',')}}"
      end

      # rubocop: disable Metrics/CyclomaticComplexity
      # rubocop: disable Metrics/PerceivedComplexity
      def msg2name(msg)
        case msg
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
        in TTTLS13::Message::CertificateVerify
          'CertificateVerify'
        in TTTLS13::Message::Finished
          'Finished'
        in TTTLS13::Message::EndOfEarlyData
          'EndOfEarlyData'
        in TTTLS13::Message::Alert
          'Alert'
        end
      end
      # rubocop: enable Metrics/CyclomaticComplexity
      # rubocop: enable Metrics/PerceivedComplexity

      # rubocop: disable Metrics/CyclomaticComplexity
      # rubocop: disable Metrics/PerceivedComplexity
      def obj2json(obj)
        case obj
        in OpenSSL::X509::Certificate
          obj.to_pem.gsub("\n", '\n')
        in Numeric, TrueClass, FalseClass
          obj.pretty_print_inspect
        in String if obj.empty?
          '""'
        in String
          "\"0x#{obj.unpack1('H*')}\""
        in NilClass
          '""'
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
