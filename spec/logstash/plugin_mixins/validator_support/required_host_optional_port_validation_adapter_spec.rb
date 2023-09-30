# encoding: utf-8

require 'logstash/plugin_mixins/validator_support/required_host_optional_port_validation_adapter'

describe LogStash::PluginMixins::ValidatorSupport::RequiredHostOptionalPortValidationAdapter do

  it 'is an instance of NamedValidationAdapter' do
    expect(described_class).to be_a_kind_of LogStash::PluginMixins::ValidatorSupport::NamedValidationAdapter
  end

  context '#validate' do
    {
      "127.0.0.1:1234" => {:host => "127.0.0.1", :port => 1234},
      "82.31.1.3:9800" => {:host => "82.31.1.3", :port => 9800},
      "foo.com:1234"   => {:host => "foo.com",   :port => 1234},
      "foo-bar-domain.com:9800" => {:host => "foo-bar-domain.com", :port => 9800},
      "[::1]:1234" => {:host => "::1", :port => 1234},
      "[2001:db8:3333:4444:5555:6666:7777:8888]:9800" => {:host => "2001:db8:3333:4444:5555:6666:7777:8888", :port => 9800},
      "[2001:db8:3333::7777:8888]:9800" => {:host => "2001:db8:3333::7777:8888", :port => 9800},
      "[::ffff:93.184.216.34]:1023" => {:host => "::ffff:93.184.216.34", :port => 1023},

      "127.0.0.1" => {:host => "127.0.0.1", :port => nil},
      "82.31.1.3" => {:host => "82.31.1.3", :port => nil},
      "foo.com"   => {:host => "foo.com",   :port => nil},
      "foo-bar-domain.com" => {:host => "foo-bar-domain.com", :port => nil},
      "[::1]" => {:host => "::1", :port => nil},
      "[2001:db8:3333:4444:5555:6666:7777:8888]" => {:host => "2001:db8:3333:4444:5555:6666:7777:8888", :port => nil},
      "[2001:db8:3333::7777:8888]" => {:host => "2001:db8:3333::7777:8888", :port => nil},
      "[::ffff:93.184.216.34]" => {:host => "::ffff:93.184.216.34", :port => nil},
    }.each do |candidate, expected_result|
      context "valid input `#{candidate.inspect}`" do
        it "coerces the result to a host/port struct `#{expected_result}`" do
          is_valid_result, coerced_or_error = described_class.validate([candidate])
          failure = is_valid_result ? nil : coerced_or_error
          coerced = is_valid_result ? coerced_or_error : nil

          aggregate_failures do
            expect(is_valid_result).to be true
            expect(failure).to be_nil # makes spec failure output useful
          end
          expect(coerced).to have_attributes(expected_result.to_h)
        end
      end
    end

    [
      "not an address",
      "http://example.com:1234",
      "tcp://example.com",
      "http://example.com:1234/v1/this",
      "",
      ":1234", # port without host
      "::1", # bare ipv6
      "2001:db8:3333:4444:5555:6666:7777:8888",
      "2001:db8:3333::7777:8888",
      "[1:2:3:4:5:6::7:8:9:a:b:c]", # invalid compressed hex ipv6 form
      "[::ffff:258.512.768.999]", # invalid compressed hex4dec ipv6 form
      "example.com:98000",
    ].each do |candidate|
      context "invalid input `#{candidate.inspect}`" do
        it "reports the input as invalid" do
          is_valid_result, coerced_or_error = described_class.validate([candidate])
          failure = is_valid_result ? nil : coerced_or_error
          coerced = is_valid_result ? coerced_or_error : nil

          aggregate_failures do
            expect(is_valid_result).to be false
            expect(coerced).to be_nil # makes spec failure output useful
          end
          expect(failure).to_not be_nil
        end
      end
    end
  end
end