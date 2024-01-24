Dir[File.dirname(__FILE__) + '/spec/*.rb'].sort.each { |f| require f }

module EchSpec
  module Spec
    class << self
      def run(fpath, port, hostname)
        # 9
        if fpath.nil?
          echconfigs = Spec9.resolve_echconfigs(hostname)
        else
          echconfigs = Spec9.parse_pem(File.open(fpath).read)
        end

        puts Spec9.is_compliant_echconfigs?(echconfigs) ? 'OK' : 'NG'

        # 7-2.3.1
        socket = TCPSocket.new(hostname, port)
        recv = Spec7_2_3_1.send_illegal_inner_ech_type(
          socket,
          hostname,
          echconfigs.first
        )
        puts recv.type == TTTLS13::Message::ContentType::ALERT && recv.messages.first.description == TTTLS13::Message::ALERT_DESCRIPTION[:illegal_parameter] ? 'OK' : 'NG'
      end
    end
  end
end
