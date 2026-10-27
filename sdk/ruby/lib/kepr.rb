# frozen_string_literal: true

# Thin client for the kepr credential daemon. Same wire format as the CLI:
# one JSON request per connection, framed by a 4-byte big-endian length,
# over the per-user Unix socket. The daemon identifies callers by socket
# credentials and applies the same rules as for the CLI (uid namespacing,
# audit, consent, sealed keys never returned).
#
# Ruby strings can't be wiped from memory: keep values in scope briefly, and
# prefer `kepr exec` / `kepr agent run` for child processes.

require 'json'
require 'socket'

module Kepr
  VERSION = '0.1.0'
  MAX_MSG_BYTES = 65_536
  GENERATE_KINDS = %w[hex base62 pass uuid words].freeze

  class Error < StandardError; end

  # Where the daemon listens, as the CLI resolves it.
  def self.socket_path(env = ENV)
    return '/run/kepr/kepr.sock' if env['KEPR_SYSTEM_MODE']

    runtime = env['XDG_RUNTIME_DIR'] ||
              File.join(env['HOME'] || '/tmp', '.local/state/kepr/runtime')
    File.join(runtime, 'kepr', 'kepr.sock')
  end

  # One `list` record as metadata; the on-disk name is dropped.
  def self.cred_info(rec)
    known = %w[name size modified cred_name expires_at record_type bound_hosts
               sealed requires_consent requires_fido2]
    info = {
      name: rec['name'], size: rec['size'], modified: rec['modified'],
      expires_at: rec['expires_at'], record_type: rec['record_type'],
      bound_hosts: rec['bound_hosts'], sealed: rec['sealed'] == true,
      requires_consent: rec['requires_consent'] == true,
      requires_fido2: rec['requires_fido2'] == true
    }
    rec.each { |k, v| info[k.to_sym] = v unless known.include?(k) } # newer daemons
    info
  end

  class Client
    def initialize(path: nil, timeout: 65)
      @path = path || Kepr.socket_path
      @timeout = timeout
    end

    # Send one raw request hash ({'cmd' => ...}); returns the reply hash.
    def request(req)
      payload = JSON.generate(req)
      raise Error, 'request too large' if payload.bytesize > MAX_MSG_BYTES

      sock = connect
      begin
        sock.write([payload.bytesize].pack('N') + payload)
        resp = read_reply(sock)
      ensure
        sock.close
      end
      raise Error, resp['error'] || 'request failed' if resp['kind'] == 'err'

      resp
    end

    def get(name)
      expect({ 'cmd' => 'get', 'name' => upper(name) }, 'get_ok')['value']
    end

    # Store +value+, or (nil) have the daemon generate one of kind +generate+
    # (default hex). A generated value is never sent back.
    def set(name, value = nil, generate: nil, ttl_secs: nil, requires_consent: false,
            requires_fido2: false)
      req = { 'cmd' => 'set', 'name' => upper(name) }
      if value.nil?
        kind = generate || 'hex'
        raise Error, "generate must be one of #{GENERATE_KINDS.join(', ')}" unless GENERATE_KINDS.include?(kind)

        req['generate'] = kind
      else
        raise Error, 'pass a value or generate, not both' if generate
        raise Error, 'value must be a non-empty string' unless value.is_a?(String) && !value.empty?

        req['value'] = value
      end
      req['ttl_secs'] = ttl_secs if ttl_secs
      req['requires_consent'] = true if requires_consent
      req['requires_fido2'] = true if requires_fido2
      expect(req, 'set_ok')
    end

    def generate(name, kind = 'hex', **opts)
      set(name, nil, generate: kind, **opts)
    end

    def delete(name)
      expect({ 'cmd' => 'delete', 'name' => upper(name) }, 'delete_ok')
      nil
    end

    # Raw credential records, as the daemon sends them.
    def list
      expect({ 'cmd' => 'list' }, 'list_ok')['credentials']
    end

    # `list` as metadata hashes; never values.
    def credentials
      list.map { |r| Kepr.cred_info(r) }
    end

    # Metadata for one credential, or nil.
    def info(name)
      n = upper(name)
      credentials.find { |c| c[:name] == n }
    end

    def history(name)
      expect({ 'cmd' => 'history', 'name' => upper(name) }, 'history_ok')['versions']
    end

    def restore(name, version)
      expect({ 'cmd' => 'restore', 'name' => upper(name), 'version' => version }, 'restore_ok')
      nil
    end

    def usage(days = nil)
      req = { 'cmd' => 'usage' }
      req['days'] = days if days
      expect(req, 'usage_ok')
    end

    def health(max_age_days = nil)
      req = { 'cmd' => 'health' }
      req['max_age_days'] = max_age_days if max_age_days
      expect(req, 'health_ok')['items']
    end

    def ssh_sign(name, data)
      r = expect({ 'cmd' => 'sshsign', 'name' => upper(name),
                   'data_b64' => [data].pack('m0') }, 'ssh_sign_ok')
      r['signature_b64'].unpack1('m')
    end

    def status
      expect({ 'cmd' => 'status' }, 'status_ok')
    end

    def ping
      expect({ 'cmd' => 'ping' }, 'pong')
      true
    end

    private

    def upper(name)
      raise Error, 'credential name must be a non-empty string' unless name.is_a?(String) && !name.empty?

      name.upcase
    end

    def expect(req, kind)
      r = request(req)
      unless r['kind'] == kind
        raise Error, 'this credential needs a FIDO2 touch; use `kepr get`' if r['kind'] == 'fido2_needed'

        raise Error, "unexpected reply: #{r['kind']}"
      end
      r
    end

    def connect
      UNIXSocket.new(@path)
    rescue SystemCallError => e
      raise Error, "cannot reach the credential service at #{@path} (#{e.class.name.split('::').last}); " \
                   'start it with `kepr-daemon --user`'
    end

    def read_reply(sock)
      head = read_exact(sock, 4) or raise Error, 'connection closed by the credential service'
      n = head.unpack1('N')
      raise Error, 'reply too large' if n > MAX_MSG_BYTES

      body = read_exact(sock, n) or raise Error, 'connection closed by the credential service'
      JSON.parse(body)
    rescue JSON::ParserError
      raise Error, 'malformed reply'
    end

    def read_exact(sock, n)
      buf = +''
      while buf.bytesize < n
        raise Error, 'timed out' unless IO.select([sock], nil, nil, @timeout)

        chunk = sock.read_nonblock(n - buf.bytesize, exception: false)
        return nil if chunk.nil?

        buf << chunk unless chunk == :wait_readable
      end
      buf
    end
  end
end
