# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require_relative '../lib/kepr'

# A fake daemon: answers each connection with the next canned reply and
# records the request it received.
class FakeDaemon
  attr_reader :requests, :path

  def initialize(dir, replies)
    @path = File.join(dir, 'kepr.sock')
    @server = UNIXServer.new(@path)
    @requests = []
    @thread = Thread.new do
      replies.each do |reply|
        conn = @server.accept
        n = conn.read(4).unpack1('N')
        @requests << JSON.parse(conn.read(n))
        out = JSON.generate(reply)
        conn.write([out.bytesize].pack('N') + out)
        conn.close
      end
    end
  end

  def finish
    @thread.join(2)
    @server.close
  end
end

class KeprTest < Minitest::Test
  def with_daemon(*replies)
    Dir.mktmpdir do |dir|
      d = FakeDaemon.new(dir, replies)
      yield Kepr::Client.new(path: d.path, timeout: 2), d
      d.finish
    end
  end

  def test_get_uppercases_the_name_and_returns_the_value
    with_daemon({ 'kind' => 'get_ok', 'name' => 'DB_PASS', 'value' => 's3cret' }) do |c, d|
      assert_equal 's3cret', c.get('db_pass')
      assert_equal({ 'cmd' => 'get', 'name' => 'DB_PASS' }, d.requests.first)
    end
  end

  def test_set_with_value_ttl_and_flags
    with_daemon({ 'kind' => 'set_ok', 'name' => 'K', 'cred_name' => 'x', 'password_protected' => true }) do |c, d|
      c.set('k', 'v', ttl_secs: 60, requires_consent: true)
      assert_equal({ 'cmd' => 'set', 'name' => 'K', 'value' => 'v', 'ttl_secs' => 60,
                     'requires_consent' => true }, d.requests.first)
    end
  end

  def test_generate_defaults_to_hex_and_checks_the_kind
    with_daemon({ 'kind' => 'set_ok', 'name' => 'K', 'cred_name' => 'x', 'password_protected' => false }) do |c, d|
      c.generate('k')
      assert_equal 'hex', d.requests.first['generate']
    end
    c = Kepr::Client.new(path: '/nonexistent')
    assert_raises(Kepr::Error) { c.generate('k', 'rot13') }
    assert_raises(Kepr::Error) { c.set('k', 'v', generate: 'hex') }
    assert_raises(Kepr::Error) { c.set('k', '') }
  end

  def test_credentials_are_metadata_with_unknown_fields_kept
    rec = { 'name' => 'A', 'size' => 3, 'modified' => 1, 'cred_name' => 'kepr-1-a',
            'sealed' => true, 'tags' => ['prod'] }
    with_daemon({ 'kind' => 'list_ok', 'credentials' => [rec] }) do |c, _|
      info = c.credentials.first
      assert_equal 'A', info[:name]
      assert info[:sealed]
      refute info.key?(:cred_name)
      assert_equal ['prod'], info[:tags]
    end
  end

  def test_error_replies_raise_with_the_daemon_message
    with_daemon({ 'kind' => 'err', 'error' => 'credential unavailable' }) do |c, _|
      err = assert_raises(Kepr::Error) { c.get('x') }
      assert_equal 'credential unavailable', err.message
    end
  end

  def test_unexpected_and_fido2_replies
    with_daemon({ 'kind' => 'pong' }, { 'kind' => 'fido2_needed' }) do |c, _|
      err = assert_raises(Kepr::Error) { c.get('x') }
      assert_match(/unexpected reply: pong/, err.message)
      err = assert_raises(Kepr::Error) { c.get('x') }
      assert_match(/FIDO2/, err.message)
    end
  end

  def test_unreachable_daemon_names_the_socket
    err = assert_raises(Kepr::Error) { Kepr::Client.new(path: '/nonexistent/kepr.sock').ping }
    assert_match(%r{/nonexistent/kepr.sock}, err.message)
  end

  def test_ssh_sign_round_trips_base64
    sig = [("\x01\x02".b)].pack('m0')
    with_daemon({ 'kind' => 'ssh_sign_ok', 'signature_b64' => sig }) do |c, d|
      assert_equal "\x01\x02".b, c.ssh_sign('key', 'data')
      assert_equal 'ZGF0YQ==', d.requests.first['data_b64']
    end
  end

  def test_socket_path_follows_the_environment
    assert_equal '/run/kepr/kepr.sock', Kepr.socket_path('KEPR_SYSTEM_MODE' => '1')
    assert_equal '/r/kepr/kepr.sock', Kepr.socket_path('XDG_RUNTIME_DIR' => '/r')
    assert_equal '/h/.local/state/kepr/runtime/kepr/kepr.sock', Kepr.socket_path('HOME' => '/h')
  end
end
