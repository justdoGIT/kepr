# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'

CORE = Dir[File.expand_path('../{libraries/kepr_lookup,lib/puppet_x/kepr/lookup}.rb', __dir__)].first
require CORE

class LookupTest < Minitest::Test
  def stub(script)
    dir = Dir.mktmpdir
    path = File.join(dir, 'kepr')
    File.write(path, "#!/bin/sh\n#{script}\n")
    File.chmod(0o755, path)
    @dirs = (@dirs || []) << dir
    path
  end

  def teardown
    (@dirs || []).each { |d| FileUtils.rm_rf(d) }
  end

  def test_returns_the_value_without_the_newline
    k = stub('[ "$1 $2 $3" = "get API_TOKEN --quiet" ] && printf "s3cret\n"')
    assert_equal 's3cret', KeprLookup.get('api_token', kepr: k)
    assert_equal 's3cret', KeprLookup.get('kepr://API_TOKEN', kepr: k)
  end

  def test_keeps_inner_newlines
    k = stub('printf "a\nb\n"')
    assert_equal "a\nb", KeprLookup.get('X', kepr: k)
  end

  def test_bad_names_never_reach_the_shell
    k = stub('echo ran >&2')
    ['A B', 'A;touch x', '../X', '', 'A' * 129].each do |n|
      assert_raises(KeprLookup::Error) { KeprLookup.get(n, kepr: k) }
    end
  end

  def test_failure_does_not_echo_output
    k = stub('echo "leaky-value"; echo "leaky-err" >&2; exit 1')
    e = assert_raises(KeprLookup::Error) { KeprLookup.get('X', kepr: k) }
    refute_match(/leaky/, e.message)
  end

  def test_missing_binary
    assert_raises(KeprLookup::Error) { KeprLookup.get('X', kepr: '/nonexistent/kepr') }
  end

  def test_timeout_kills_the_child
    k = stub('sleep 30')
    t = Time.now
    assert_raises(KeprLookup::Error) { KeprLookup.get('X', kepr: k, wait: 0.5) }
    assert_operator Time.now - t, :<, 5
  end
end
