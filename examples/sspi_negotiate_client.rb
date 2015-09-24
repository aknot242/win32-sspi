require 'pp'
require 'base64'
require 'net/http'
require 'win32/sspi/negotiate/client'

class RubySSPIClient
  def self.run(url)
    uri = URI.parse(url)
    client = Win32::SSPI::Negotiate::Client.new("HTTP/#{uri.host}")
    client.acquire_handle
    status,token = client.initialize_context
    
    Net::HTTP.start(uri.host, uri.port) do |http|
      while client.status_continue(status)
        req = Net::HTTP::Get.new(uri.path)
        req['Authorization'] = "#{client.auth_type} #{Base64.strict_encode64(token)}"
        resp = http.request(req)
        header = resp['www-authenticate']
        if header
          auth_type, token = header.split(' ')
          token = Base64.strict_decode64(token)
          status,token = client.initialize_context(token)
        end
      end
      
      puts resp.body if resp.body
    end
  end
end

if __FILE__ == $0
  if ARGV.length < 1
    puts "usage: ruby -Ilib examples/sspi_negotiate_client.rb url"
    puts "where: url = http://hostname:port/path"
    exit(0)
  end

  RubySSPIClient.run(ARGV[0])
end
