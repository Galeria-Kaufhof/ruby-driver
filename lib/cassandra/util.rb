# encoding: utf-8

#--
# Copyright 2013-2015 DataStax, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#++

module Cassandra
  # @private
  module Util extend self
    def encode_hash(hash, io = StringIO.new)
      first = true

      io.putc(CRL_OPN)
      hash.each do |k, v|
        if first
          first = false
        else
          io.print(COMMA)
        end

        encode_object(k, io)
        io.print(COLON)
        encode_object(v, io)
      end
      io.putc(CRL_CLS)

      io.string
    end

    def encode_set(set, io = StringIO.new)
      first = true

      io.putc(CRL_OPN)
      set.each do |object|
        if first
          first = false
        else
          io.print(COMMA)
        end

        encode_object(object, io)
      end
      io.putc(CRL_CLS)

      io.string
    end

    def encode_array(array, io = StringIO.new)
      first = true

      io.putc(SQR_OPN)
      array.each do |object|
        if first
          first = false
        else
          io.print(COMMA)
        end

        encode_object(object, io)
      end
      io.putc(SQR_CLS)

      io.string
    end

    def encode_string(string, io = StringIO.new)
      io.putc(QUOT)
      string.chars do |c|
        case c
        when QUOT then io.print(ESC_QUOT)
        else
          io.putc(c)
        end
      end
      io.putc(QUOT)

      io.string
    end

    def encode_object(object, io = StringIO.new)
      case object
      when ::Hash    then encode_hash(object, io)
      when ::Array   then encode_array(object, io)
      when ::Set     then encode_set(object, io)
      when ::String  then encode_string(object, io)
      when ::Time    then encode_timestamp(object, io)
      when ::Numeric then encode_number(object, io)
      when ::IPAddr  then encode_inet(object, io)
      when Uuid      then encode_uuid(object, io)
      when nil       then io.print(NULL_STR)
      when false     then io.print(FALSE_STR)
      when true      then io.print(TRUE_STR)
      else
        raise ::ArgumentError, "unsupported type: #{object.inspect}"
      end

      io.string
    end
    alias :encode :encode_object

    def encode_timestamp(time, io = StringIO.new)
      io.print(time.to_i)
      io.string
    end

    def encode_number(number, io = StringIO.new)
      io.print(number)
      io.string
    end

    def encode_uuid(uuid, io = StringIO.new)
      io.print(uuid)
      io.string
    end

    def encode_inet(inet, io = StringIO.new)
      io.putc(QUOT)
      io.print(inet)
      io.putc(QUOT)
      io.string
    end

    def escape_name(name)
      return name if name[LOWERCASE_REGEXP] == name
      DBL_QUOT + name + DBL_QUOT
    end

    def guess_type(object)
      case object
      when ::String      then Types.varchar
      when ::Fixnum      then Types.bigint
      when ::Float       then Types.double
      when ::Bignum      then Types.varint
      when ::BigDecimal  then Types.decimal
      when ::TrueClass   then Types.boolean
      when ::FalseClass  then Types.boolean
      when ::NilClass    then Types.bigint
      when Uuid          then Types.uuid
      when TimeUuid      then Types.timeuuid
      when ::IPAddr      then Types.inet
      when ::Time        then Types.timestamp
      when ::Hash
        pair = object.first
        Types.map(guess_type(pair[0]), guess_type(pair[1]))
      when ::Array       then Types.list(guess_type(object.first))
      when ::Set         then Types.set(guess_type(object.first))
      when Tuple::Strict then Types.tuple(*object.types)
      when Tuple         then Types.tuple(*object.map {|v| guess_type(v)})
      when UDT::Strict
        Types.udt(object.keyspace, object.name, object.types)
      when UDT
        Types.udt('unknown', 'unknown', object.map {|k, v| [k, guess_type(v)]})
      else
        raise ::ArgumentError, "Unable to guess the type of the argument: #{object.inspect}"
      end
    end

    def assert_type(type, value, message = nil, &block)
      assert_instance_of(Cassandra::Type, type, message, &block)
      return if value.nil?
      type.assert(value, message, &block)
    end

    def assert_instance_of(kind, value, message = nil, &block)
      unless value.is_a?(kind)
        message   = yield if block_given?
        message ||= "value must be an instance of #{kind}, #{value.inspect} given"

        raise ::ArgumentError, message
      end
    end

    def assert_instance_of_one_of(kinds, value, message = nil, &block)
      unless kinds.any? {|kind| value.is_a?(kind)}
        message   = yield if block_given?
        message ||= "value must be an instance of one of #{kinds.inspect}, #{value.inspect} given"

        raise ::ArgumentError, message
      end
    end

    def assert_responds_to(method, value, message = nil, &block)
      unless value.respond_to?(method)
        message   = yield if block_given?
        message ||= "value #{value.inspect} must respond to #{method.inspect}, but doesn't"

        raise ::ArgumentError, message
      end
    end

    def assert_responds_to_all(methods, value, message = nil, &block)
      unless methods.all? {|method| value.respond_to?(method)}
        message   = yield if block_given?
        message ||= "value #{value.inspect} must respond to all methods #{methods.inspect}, but doesn't"

        raise ::ArgumentError, message
      end
    end

    def assert_not_empty(value, message = nil, &block)
      if value.empty?
        message   = yield if block_given?
        message ||= "value cannot be empty"

        raise ::ArgumentError, message
      end
    end

    def assert_file_exists(path, message = nil, &block)
      unless ::File.exists?(path)
        message   = yield if block_given?
        message ||= "expected file at #{path.inspect} to exist, but it doesn't"

        raise ::ArgumentError, message
      end
    end

    def assert_one_of(range, value, message = nil, &block)
      unless range.include?(value)
        message   = yield if block_given?
        message ||= "value must be included in #{value.inspect}, #{value.inspect} given"

        raise ::ArgumentError, message
      end
    end

    def assert_size(size, value, message = nil, &block)
      unless value.size == size
        message   = yield if block_given?
        message ||= "value #{value.inspect} must have size equal to #{size.inspect}, but doesn't"

        raise ::ArgumentError, message
      end
    end

    def assert(condition, message = nil, &block)
      unless condition
        message   = yield if block_given?
        message ||= "assertion failed"

        raise ::ArgumentError, message
      end
    end

    def assert_equal(expected, actual, message = nil, &block)
      unless expected == actual
        message   = yield if block_given?
        message ||= "expected #{actual.inspect} to equal #{expected.inspect}"

        raise ::ArgumentError, message
      end
    end

    def assert_nil_or_numeric_greater_zero(value, name = 'unknown')
      return true if value.nil?
      Util.assert_instance_of(::Numeric, timeout) { ":#{name} must be a number of seconds, #{value} given" }
      Util.assert(timeout > 0) { ":#{name} must be greater than 0, #{value} given" }
    end

    # @private
    LOWERCASE_REGEXP = /[[:lower:]\_]*/
    # @private
    NULL_STR = 'null'.freeze
    # @private
    FALSE_STR = 'false'.freeze
    # @private
    TRUE_STR = 'true'.freeze
    # @private
    CRL_OPN = '{'.freeze
    # @private
    CRL_CLS = '}'.freeze
    # @private
    SQR_OPN = '['.freeze
    # @private
    SQR_CLS = ']'.freeze
    # @private
    COMMA = ', '.freeze
    # @private
    COLON = ' : '.freeze
    # @private
    QUOT = ?'.freeze
    # @private
    ESC_QUOT = "''".freeze
    # @private
    DBL_QUOT = ?".freeze
  end
end
