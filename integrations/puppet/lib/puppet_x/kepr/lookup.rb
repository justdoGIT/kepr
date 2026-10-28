# frozen_string_literal: true

require 'open3'
require 'timeout'

module KeprLookup
  class Error < StandardError; end

  NAME = /\A[A-Za-z0-9_]{1,128}\z/.freeze
  WAIT = 65 # seconds; covers the daemon's consent prompt

  # The value of credential +name+: `kepr get NAME --quiet`, run as the
  # calling user. The name goes in argv as one element (no shell). Errors
  # never carry the value or the CLI's output.
  def self.get(name, kepr: ENV.fetch('KEPR_BIN', 'kepr'), wait: WAIT)
    name = name.to_s.sub(%r{\Akepr://}, '').upcase
    raise Error, 'credential names are A-Z, 0-9 and _' unless NAME.match?(name)

    out = status = nil
    Open3.popen3(kepr, 'get', name, '--quiet') do |stdin, stdout, stderr, thr|
      stdin.close
      begin
        Timeout.timeout(wait) do
          reader = Thread.new { stderr.read }
          out = stdout.read
          reader.join
          status = thr.value
        end
      rescue Timeout::Error
        begin
          Process.kill('KILL', thr.pid)
        rescue StandardError
          nil
        end
        raise Error, "kepr did not answer for #{name}"
      end
    end
    raise Error, "kepr could not read #{name}" unless status&.success?

    out.chomp
  rescue SystemCallError
    raise Error, 'kepr is not installed or not on the PATH'
  end
end
