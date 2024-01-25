module EchSpec
  class Ok
    attr_accessor :message

    def initialize(message)
      @message = message
    end

    def deconstruct
      [@message]
    end
  end

  class Err
    attr_accessor :message

    def initialize(message)
      @message = message
    end

    def deconstruct
      [@message]
    end
  end
end
