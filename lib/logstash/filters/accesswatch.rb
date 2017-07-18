# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'net/http'
require 'json'
require 'digest'
require 'lru_redux'

# The Access Watch filter adds information about robots visiting
# your website based on data from our robots database.

class LogStash::Filters::Accesswatch < LogStash::Filters::Base

  config_name "accesswatch"

  # Your API Key
  config :api_key, :validate => :string, :required => true

  # The size of the local cache, 0 to deactivate
  config :cache_size, :validate => :number, :default => 10000

  # The read timeout for the HTTP request to the service
  config :read_timeout, :validate => :number, :default => 1

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

  @@address_keys = ['value', 'hostname', 'country_code', 'flags']
  @@robot_keys = ['id', 'name', 'url']

  public
  def register
    @http_client = Net::HTTP.start('api.access.watch', 80, :read_timeout => @read_timeout)
    if @cache_size > 0
      @cache = LruRedux::ThreadSafeCache.new(@cache_size)
    end
  end

  def fetch_data(aw_request)
    begin
      http_request = aw_request[:http_request]
      http_request['Api-Key'] = @api_key
      http_request['Accept'] = 'application/json'
      http_request['User Agent'] = "Access Watch Logstash Filter Plugin/0.1"
      http_response = @http_client.request http_request
      if http_response.code != '200'
        {:status      => :error,
         :http_status => http_response.code,
         :message     => 'AccessWatch: Could not fetch data for this object.'}
      else
        {:status => :success,
         :data   => JSON.parse(http_response.body)}
      end
    rescue Net::ReadTimeout
      {:status => :timeout}
    end
  end

  def cached_fetch_data(aw_request)
    if @cache
      @cache.getset(aw_request[:id]){
        self.fetch_data(aw_request)
      }
    else
      self.fetch_data(aw_request)
    end
  end

  def fetch_address(ip)
    self.cached_fetch_data({:id           => "ip-#{ip}",
                            :http_request => Net::HTTP::Get.new("/1.1/address/#{ip}")})
  end

  def fetch_user_agent(user_agent)
    http_request = Net::HTTP::Post.new('/1.1/user-agent')
    http_request.body = JSON.generate({:value => user_agent})
    http_request.content_type = 'application/json'
    id = "ua-#{Digest::MD5.hexdigest(user_agent)}"
    self.cached_fetch_data({:id           => id,
                            :http_request => http_request})
  end

  def fetch_identity(ip, user_agent)
    ip = ip || ''
    user_agent = user_agent || ''
    http_request = Net::HTTP::Post.new('/1.1/identity')
    http_request.body = JSON.generate({:address => ip,
                                       :user_agent => user_agent})
    http_request.content_type = 'application/json'
    id = "identity-#{Digest::MD5.hexdigest(ip)}-#{Digest::MD5.hexdigest(user_agent)}"
    self.cached_fetch_data({:id           => id,
                            :http_request => http_request})
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
    ip = event.get(@ip_source)
    user_agent = event.get(@user_agent_source)
    if @ip_source and @user_agent_source
      data = self.fetch_identity(ip, user_agent)
      self.augment(event, @address_destination, data[:address], @@address_keys)
      self.augment(event, @robot_destination, data[:robot], @@robot_keys)
      self.augment(event, @reputation_destination, data[:reputation])
    elsif @ip_source
      data = self.fetch_address(ip)
      self.augment(event, @address_destination, data, @@address_keys)
    else
      data = self.fetch_user_agent(user_agent)
      self.augment(event, @user_agent_destination, data)
    end
    filter_matched(event)
  end

end
