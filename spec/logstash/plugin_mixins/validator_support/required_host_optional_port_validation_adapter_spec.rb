# encoding: utf-8

require 'logstash/plugin_mixins/validator_support/host_port_pair_validation_adapter'

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
      "::1" => {:host => "::1", :port => nil},
      "[::1]" => {:host => "::1", :port => nil},
      "2001:db8:3333:4444:5555:6666:7777:8888" => {:host => "2001:db8:3333:4444:5555:6666:7777:8888", :port => nil},
      "[2001:db8:3333:4444:5555:6666:7777:8888]" => {:host => "2001:db8:3333:4444:5555:6666:7777:8888", :port => nil},
      "2001:db8:3333::7777:8888" => {:host => "2001:db8:3333::7777:8888", :port => nil},
      "[2001:db8:3333::7777:8888]" => {:host => "2001:db8:3333::7777:8888", :port => nil},
      "::ffff:93.184.216.34" => {:host => "::ffff:93.184.216.34", :port => nil},
      "[::ffff:93.184.216.34]" => {:host => "::ffff:93.184.216.34", :port => nil},
    }.each do |candidate, expected_result|
      context "valid input `#{candidate.inspect}`" do
        it 'coerces the result to a host/port struct' do
          is_valid_result, coerced_or_error = described_class.validate([candidate])
          aggregate_failures do
            expect(is_valid_result).to be true
            expect(coerced_or_error).to have_attributes(expected_result.to_h)
          end
        end
      end
    end
  end
end