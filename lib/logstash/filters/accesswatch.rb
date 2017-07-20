# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "logstash/plugin_mixins/http_client"
require "json"
require "digest"
require "lru_redux"

# The Access Watch filter adds information about robots visiting
# your website based on data from our robots database.

class LogStash::Filters::Accesswatch < LogStash::Filters::Base

  include LogStash::PluginMixins::HttpClient

  config_name "accesswatch"

  # Your API Key
  config :api_key, :validate => :string, :required => true

  # The size of the local cache, 0 to deactivate
  config :cache_size, :validate => :number, :default => 10000

  # The field containing the IP address.
  config :ip_source, :validate => :string, :required => true

  # The field containing the User-Agent string.
  config :user_agent_source, :validate => :string, :required => true

  # The destination field for address data
  config :address_destination, :validate => :string

  # The destination field for user-agent data
  config :user_agent_destination, :validate => :string

  # The destination field for robot data
  config :robot_destination, :validate => :string

  # The destination field for reputation data
  config :reputation_destination, :validate => :string

  @@address_keys = ["value", "hostname", "country_code", "flags"]
  @@robot_keys = ["id", "name", "url"]

  public
  def register
    if @cache_size > 0
      @cache = LruRedux::ThreadSafeCache.new(@cache_size)
    end
  end

  def submit(&block)
    http_response = block.call
    data = JSON.parse(http_response.body)
    if http_response.code != 200
      raise "Access Watch (#{data["code"]}): #{data["message"]}"
    end
    data
  end

  def url(path)
    "http://api.access.watch#{path}"
  end

  def get_json(path)
    self.submit {
      self.client.get(self.url(path),
                      headers: {"Api-Key"    => @api_key,
                                "Accept"     => "application/json",
                                "User-Agent" => "Access Watch Logstash Plugin/0.2.0"})
    }
  end

  def post_json(path, data)
    self.submit {
      self.client.post(self.url(path),
                       headers: {"Api-Key"      => @api_key,
                                 "Accept"       => "application/json",
                                 "Content-Type" => "application/json",
                                 "User-Agent"   => "Access Watch Logstash Plugin/0.2.0"},
                       body: JSON.generate(data))
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
    ip = ip || ""
    user_agent = user_agent || ""
    self.with_cache("identity-#{Digest::MD5.hexdigest(ip)}-#{Digest::MD5.hexdigest(user_agent)}") {
      self.post_json("/1.1/identity", {:address => ip, :user_agent => user_agent})
    }
  end

  def augment(event, destination, data, keys=nil)
    if destination && data
      event.set(destination,
                data.select {|k, v|
                  (keys.nil? or keys.include?(k)) && !(v.nil? || v.empty?)
                })
    end
  end

  public
  def filter(event)
    begin
      ip = event.get(@ip_source)
      user_agent = event.get(@user_agent_source)
      if @ip_source and @user_agent_source
        data = self.fetch_identity(ip, user_agent)
        self.augment(event, @address_destination, data["address"], @@address_keys)
        self.augment(event, @robot_destination, data["robot"], @@robot_keys)
        self.augment(event, @reputation_destination, data["reputation"])
      elsif @ip_source
        data = self.fetch_address(ip)
        self.augment(event, @address_destination, data, @@address_keys)
      else
        data = self.fetch_user_agent(user_agent)
        self.augment(event, @user_agent_destination, data)
      end
    rescue => e
      @logger.error("Error augmenting the data.", error: e)
    end
    filter_matched(event)
  end

end
