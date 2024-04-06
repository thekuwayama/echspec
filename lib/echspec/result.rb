module EchSpec
  class Ok
    attr_reader :obj

    def initialize(obj)
      @obj = obj
    end

    def deconstruct
      [@obj]
    end
  end

  class Err
    attr_reader :details, :message_stack

    def initialize(details, message_stack)
      @details = details
      @message_stack = message_stack
    end

    def deconstruct
      [@details, @message_stack]
    end
  end
end
