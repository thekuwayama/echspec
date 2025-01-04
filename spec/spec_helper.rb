RSpec.configure(&:disable_monkey_patching!)

require 'echspec'

class C
  def initialize(name)
    @name = name
  end
end

class D
end
