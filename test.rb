require "manticore"
require "json"
require "digest"
require "lru_redux"
require 'net/http'

class AccessWatchClient

  def initialize(api_key, cache_size=10000)
    @client = Manticore::Client.new ssl: {ca_file: "cert.pem"}
    @api_key = api_key
    if cache_size > 0
      @cache = LruRedux::ThreadSafeCache.new(cache_size)
    end
  end

  def handle_response(response)
    data = JSON.parse(response.body)
    if response.code == 200
      {:status => :success,
       :data   => data}
    else
      {:status  => :error,
       :code    => data["code"],
       :message => data["message"]}
    end
  end

  def url(path)
    "https://api.access.watch#{path}"
  end

  def submit(&block)
    begin
      block.call
    rescue => e
      {:status => :error,
       :error  => e,
       :message => e.message}
    end
  end

  def get_json(path)
    self.submit {
      self.handle_response(@client.get(self.url(path),
                                       headers: {"Api-Key"    => @api_key,
                                                 "Accept"     => "application/json",
                                                 "User-Agent" => "Access Watch Logstash Plugin/0.2.0"}))
    }
  end

  def post_json(path, data)
    self.submit {
      self.handle_response(@client.post(self.url(path),
                                        headers: {"Api-Key"      => @api_key,
                                                  "Accept"       => "application/json",
                                                  "Content-Type" => "application/json",
                                                  "User-Agent"   => "Access Watch Logstash Plugin/0.2.0"},
                                        body: JSON.generate(data)))
    }
  end

  def with_cache(id, &block)
    if @cache
      @cache.getset(id) { block.call }
    else
      block.call
    end
  end

  def fetch_address(ip)
    self.with_cache("ip-#{ip}") {
      self.get_json("/1.1/address/#{ip}")
    }
  end

  def fetch_user_agent(user_agent)
    self.with_cache("ua-#{Digest::MD5.hexdigest(user_agent)}") {
      self.post_json("/1.1/user-agent", {:value => user_agent})
    }
  end

  def fetch_identity(ip, user_agent)
    ip = ip || ''
    user_agent = user_agent || ''
    self.with_cache("identity-#{Digest::MD5.hexdigest(ip)}-#{Digest::MD5.hexdigest(user_agent)}") {
      self.post_json("/1.1/identity", {:address => ip, :user_agent => user_agent})
    }
  end

  def test
    p self.fetch_address("127.0.0.1")
    p "---"
    p self.fetch_user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.125 Safari/537.36")
    p "---"
    p self.fetch_identity("77.123.68.232", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.125 Safari/537.36")
  end

end

client = AccessWatchClient.new("94bbc755f5b8aa96cfd40ce97faad568")
p client.fetch_address("127.0.0.1")
