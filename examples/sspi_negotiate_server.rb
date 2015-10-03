# Attempting to setup an example authenticating server
require 'base64'
require 'webrick'
unless ENV['WIN32_SSPI_TEST']
  require 'win32-sspi'
  require 'negotiate/server'
else
  require 'win32/sspi/negotiate/server'
  puts "!!!! running with test environment !!!"
end

# A way to store state across multiple requests
class StateStore
  def self.state
    @state ||= Hash.new
  end
  
  def self.store_state(key,value)
    state[key] = value
  end
  
  def self.retrieve_state(key)
    state[key]
  end
  
  def self.clear_state
    state.clear
  end
  
  def self.retrieve_server
    state[:server] ||= Win32::SSPI::Negotiate::Server.new
    state[:server]
  end
end


class RubySSPIServlet < WEBrick::HTTPServlet::AbstractServlet
  def do_GET(req,resp)
    if req['Authorization'].nil? || req['Authorization'].empty?
      resp['www-authenticate'] = 'Negotiate'
      resp.status = 401
      return
    end

    auth_type, token = req['Authorization'].split(" ")
    token = Base64.strict_decode64(token)

    sspi_server = StateStore.retrieve_server
    if sspi_server.authenticate_and_continue?(token)
      token = Base64.strict_encode64(sspi_server.token)
      resp['www-authenticate'] = "#{auth_type} #{token}"
      resp.status = 401
      return
    end
    
    resp['Remote-User'] = sspi_server.username
    resp['Remote-User-Domain'] = sspi_server.domain
    resp.status = 200
    resp['Content-Type'] = "text/plain"
    resp.body = "#{Time.now}: Hello #{sspi_server.username} at #{sspi_server.domain}"
    if sspi_server.token && sspi_server.token.length > 0
      token = Base64.strict_encode64(sspi_server.token)
      resp['www-authenticate'] = "#{auth_type} #{token}"
    end
    
    StateStore.clear_state
  end

  def self.run(url)
    uri = URI.parse(url)
    s = WEBrick::HTTPServer.new( :Binding=>uri.host, :Port=>uri.port)
    s.mount(uri.path, RubySSPIServlet)
    trap("INT") { s.shutdown }
    s.start
  end
end

if $0 == __FILE__
  if ARGV.length < 1
    puts "usage: ruby sspi_negotiate_server.rb url"
    puts "where: url = http://hostname:port/path"
    exit(0)
  end
  
  RubySSPIServlet.run(ARGV[0])
end
